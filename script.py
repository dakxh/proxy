import asyncio
import aiohttp
import json
import re
import sys
import os
import time
import maxminddb
import logging
from aiohttp_socks import ProxyConnector, ProxyError, ProxyConnectionError, ProxyTimeoutError

# --- CONFIGURATION ---
TIMEOUT = 4.0
MAX_CONCURRENT_CHECKERS = 60 # Set to 60 for stability
STATUS_UPDATE_INTERVAL = 50  # Log progress every 50 checks
DB_PATH = 'GeoLite2-Country.mmdb'
DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

# Setup Logging
logger = logging.getLogger("ProxyCollector")
logger.setLevel(logging.INFO)
if logger.hasHandlers(): logger.handlers.clear()
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(handler)

OUT_FILES = {
    "http": "IN_HTTP_PROXIES.TXT",
    "https": "IN_HTTPS_PROXIES.TXT",
    "socks4": "IN_SOCKS4_PROXIES.TXT",
    "socks5": "IN_SOCKS5_PROXIES.TXT"
}

# Regex
RE_STRICT_URI = re.compile(r'^(http|https|socks4|socks5)://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', re.IGNORECASE)
RE_IP_PORT = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s](\d+)')

class StrictProxyCollector:
    def __init__(self):
        self.raw_proxies = []
        self.final_proxies = {k: set() for k in OUT_FILES.keys()}
        self.seen_entries = set()
        self.geo_reader = None
        self.processed_count = 0
        self.total_candidates = 0

    def add(self, ip, port, proto, check_geo, source="unknown"):
        try:
            proto = proto.lower() if proto else None
            key = f"{ip}:{port}"
            if key in self.seen_entries: return
            self.raw_proxies.append({'ip': ip, 'port': port, 'proto': proto, 'check_geo': check_geo, 'src': source})
            self.seen_entries.add(key)
        except Exception: pass

    async def ensure_db_exists(self):
        if os.path.exists(DB_PATH):
            logger.info("GeoIP Database found locally.")
            return
        logger.info(f"Downloading GeoIP Database from {DB_URL}...")
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(DB_URL) as resp:
                    if resp.status == 200:
                        with open(DB_PATH, 'wb') as f: f.write(await resp.read())
                        logger.info("DB Downloaded.")
                    else:
                        logger.error(f"Failed to download DB: HTTP {resp.status}")
        except Exception as e:
            logger.error(f"Download Error: {e}")

    # --- PARSERS (Safe Mode) ---
    def parse_plain_ip_port(self, text, fixed_proto, check_geo, src):
        c = 0
        for line in text.splitlines():
            m = RE_IP_PORT.search(line)
            if m:
                self.add(m.group(1), m.group(2), fixed_proto, check_geo, src)
                c+=1
        return c

    def parse_mixed_uri(self, text, check_geo, src):
        c = 0
        for line in text.splitlines():
            line = line.strip()
            if not line: continue
            m = RE_STRICT_URI.match(line)
            if m:
                self.add(m.group(2), m.group(3), m.group(1), check_geo, src)
                c+=1
            else:
                m2 = RE_IP_PORT.search(line)
                if m2:
                    self.add(m2.group(1), m2.group(2), None, check_geo, src)
                    c+=1
        return c

    def parse_json_generic(self, text, parser_type, src):
        c = 0
        try:
            data = json.loads(text)

            # Helper to safely get nested keys without crashing on None
            def safe_get(d, keys):
                for k in keys:
                    if isinstance(d, dict): d = d.get(k)
                    else: return None
                return d

            if parser_type == 'set3': # Bes-js
                items = data if isinstance(data, list) else []
                for item in items:
                    if safe_get(item, ['geolocation', 'countryCode']) == "IN":
                        self.add(item.get('ip'), item.get('port'), item.get('protocol', 'http'), False, src)
                        c+=1

            elif parser_type == 'set14': # Monosans (Fixed Crash Here)
                items = data if isinstance(data, list) else []
                for item in items:
                    # Defensive coding: get('geolocation') or {} handles None return
                    geo = item.get('geolocation') or {}
                    country = geo.get('country') or {}
                    if country.get('iso_code') == 'IN':
                        host = item.get('host') or item.get('ip')
                        self.add(host, item.get('port'), item.get('protocol'), False, src)
                        c+=1

            elif parser_type == 'set19': # MauriceGift
                if isinstance(data, dict):
                    for k, v in data.items():
                        if v.get('countryCode') == 'IN':
                            m = RE_STRICT_URI.match(k)
                            if m:
                                self.add(m.group(2), m.group(3), m.group(1), False, src)
                                c+=1

            elif parser_type == 'set20': # Themiralay
                items = data if isinstance(data, list) else []
                for item in items:
                    if safe_get(item, ['geolocation', 'countryCode']) == 'IN':
                        self.add(item.get('ip'), item.get('port'), None, False, src)
                        c+=1

        except Exception as e:
            # We skip failed JSON but don't crash the script
            pass
        return c

    def parse_ndjson(self, text, src):
        c = 0
        for line in text.splitlines():
            try:
                item = json.loads(line)
                if item.get('country') in ['IN', 'India']:
                    self.add(item.get('host'), item.get('port'), item.get('type'), False, src)
                    c+=1
            except: pass
        return c

    async def fetch_source(self, session, url, parser_func, **kwargs):
        src_name = url.split('/')[-1]
        try:
            async with session.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    count = 0
                    if parser_func == 'plain':
                        count = self.parse_plain_ip_port(text, kwargs.get('proto'), kwargs.get('geo'), src_name)
                    elif parser_func == 'uri':
                        count = self.parse_mixed_uri(text, kwargs.get('geo'), src_name)
                    elif parser_func == 'ndjson':
                        count = self.parse_ndjson(text, src_name)
                    elif parser_func == 'set13':
                        count = self.parse_plain_ip_port(text, None, True, src_name)
                    else:
                        count = self.parse_json_generic(text, parser_func, src_name)

                    logger.info(f"OK: {src_name} ({count} items)")
                else:
                    logger.warning(f"FAIL: {src_name} [HTTP {resp.status}]")
        except Exception as e:
            logger.warning(f"ERR: {src_name} [{str(e)[:30]}...]")

    def run_geo_filter(self):
        try:
            self.geo_reader = maxminddb.open_database(DB_PATH)
        except:
            logger.error("CRITICAL: GeoDB not found. Cannot filter!")
            self.raw_proxies = []
            return

        logger.info(f"Filtering {len(self.raw_proxies)} candidates for India...")
        in_proxies = []
        for p in self.raw_proxies:
            if not p['check_geo']:
                in_proxies.append(p)
                continue
            try:
                res = self.geo_reader.get(p['ip'])
                if res and res.get('country', {}).get('iso_code') == 'IN':
                    in_proxies.append(p)
            except: pass

        self.geo_reader.close()
        self.raw_proxies = in_proxies
        logger.info(f"Geo Filter Complete. India Candidates: {len(self.raw_proxies)}")

    async def verify_batch(self, p, sem, session):
        async with sem:
            ip, port, proto = p['ip'], p['port'], p['proto']
            result = False

            # Simple waterfall
            if proto:
                if await self._check(session, ip, port, proto):
                    self.final_proxies[proto].add(f"{ip}:{port}")
                    result = True
            else:
                strategies = ['socks5', 'socks4', 'https', 'http']
                if str(port) in ['80', '8080', '3128']: strategies = ['http', 'https', 'socks5', 'socks4']
                for s in strategies:
                    if await self._check(session, ip, port, s):
                        self.final_proxies[s].add(f"{ip}:{port}")
                        result = True
                        break

            self.processed_count += 1
            if self.processed_count % STATUS_UPDATE_INTERVAL == 0:
                alive = sum(len(v) for v in self.final_proxies.values())
                pct = (self.processed_count / self.total_candidates) * 100
                logger.info(f"Checked {self.processed_count}/{self.total_candidates} ({pct:.1f}%) - Found {alive} Alive")

    async def _check(self, session, ip, port, proto):
        target = "http://httpbin.org/ip"
        prox_url = f"{proto}://{ip}:{port}"
        if proto == 'https':
            prox_url = f"http://{ip}:{port}"
            target = "https://httpbin.org/ip"
        elif proto == 'http':
            prox_url = f"http://{ip}:{port}"

        try:
            connector = ProxyConnector.from_url(prox_url)
            async with aiohttp.ClientSession(connector=connector) as sess:
                async with sess.get(target, timeout=TIMEOUT) as resp:
                    return resp.status == 200
        except: return False

    async def pipeline(self):
        print("\n=== STARTING PROXY COLLECTOR ===")
        await self.ensure_db_exists()

        async with aiohttp.ClientSession() as session:
            tasks = []

            # --- URLs Definitions ---
            set1 = [
                ("https://raw.githubusercontent.com/RioMMO/ProxyFree/refs/heads/main/HTTP.txt", 'http'),
                ("https://raw.githubusercontent.com/RioMMO/ProxyFree/refs/heads/main/SOCKS4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/RioMMO/ProxyFree/refs/heads/main/SOCKS5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/http/raw/country/IN.txt", 'http'),
                ("https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks4/raw/country/IN.txt", 'socks4'),
                ("https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/refs/heads/main/socks5/raw/country/IN.txt", 'socks5'),
                ("https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/India.txt", 'http'),
                ("https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/https/India.txt", 'https'),
                ("https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/socks4/India.txt", 'socks4'),
                ("https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/socks5/India.txt", 'socks5'),
                ("https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/country/India/socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/country/India/socks4.txt", 'socks4'),
            ]
            for u, p in set1: tasks.append(self.fetch_source(session, u, 'plain', proto=p, geo=False))

            set2 = [
                ("https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt", 'http'),
                ("https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/https.txt", 'https'),
                ("https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/http.txt", 'http'),
                ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/https.txt", 'https'),
                ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/TuanMinPay/live-proxy/refs/heads/master/http.txt", 'http'),
                ("https://raw.githubusercontent.com/TuanMinPay/live-proxy/refs/heads/master/socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/TuanMinPay/live-proxy/refs/heads/master/socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Https.txt", 'https'),
                ("https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/http-proxy-list-by-EbraSha.txt", 'http'),
                ("https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/https-proxy-list-by-EbraSha.txt", 'https'),
                ("https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/socks4-proxy-list-by-EbraSha.txt", 'socks4'),
                ("https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/socks5-proxy-list-by-EbraSha.txt", 'socks5'),
                ("https://raw.githubusercontent.com/krokmazagaga/http-proxy-list/refs/heads/main/http.txt", 'http'),
                ("https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt", 'socks5'),
                ("https://raw.githubusercontent.com/0x1881/Free-Proxy-List/refs/heads/main/http.txt", 'http'),
                ("https://raw.githubusercontent.com/0x1881/Free-Proxy-List/refs/heads/main/https.txt", 'https'),
                ("https://raw.githubusercontent.com/0x1881/Free-Proxy-List/refs/heads/main/socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/0x1881/Free-Proxy-List/refs/heads/main/socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/Skillter/ProxyGather/refs/heads/master/proxies/working-proxies-http.txt", 'http'),
                ("https://raw.githubusercontent.com/Skillter/ProxyGather/refs/heads/master/proxies/working-proxies-socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/Skillter/ProxyGather/refs/heads/master/proxies/working-proxies-socks5.txt", 'socks5'),
                ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt", 'http'),
                ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt", 'https'),
                ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt", 'socks4'),
                ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks5.txt", 'socks5'),
            ]
            for u, p in set2: tasks.append(self.fetch_source(session, u, 'plain', proto=p, geo=True))

            set3 = [
                "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
                "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",
                "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
                "https://raw.githubusercontent.com/stormsia/proxy-list/refs/heads/main/working_proxies.txt",
                "https://raw.githubusercontent.com/Cheagjihvg/simple-proxylist/refs/heads/main/proxy.txt"
            ]
            for u in set3: tasks.append(self.fetch_source(session, u, 'uri', geo=True))

            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/refs/heads/main/proxylist.txt", 'set13'))
            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/Bes-js/public-proxy-list/refs/heads/main/proxies_geolocation.json", 'set3'))
            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies_pretty.json", 'set14'))
            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/mauricegift/free-proxies/refs/heads/master/files/metadata.json", 'set19'))
            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/themiralay/Proxy-List-World/refs/heads/master/data-with-geolocation.json", 'set20'))
            tasks.append(self.fetch_source(session, "https://raw.githubusercontent.com/arunsakthivel96/proxyBEE/refs/heads/master/proxy.list", 'ndjson'))

            logger.info("Harvesting Proxies...")
            await asyncio.gather(*tasks)

        self.run_geo_filter()

        self.total_candidates = len(self.raw_proxies)
        if self.total_candidates == 0:
            logger.error("No valid candidates found to check.")
            return

        logger.info(f"Beginning Aliveness Check for {self.total_candidates} candidates.")
        sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKERS)

        async with aiohttp.ClientSession() as check_session:
            await asyncio.gather(*[self.verify_batch(p, sem, check_session) for p in self.raw_proxies])

        print("\n\n=== SUMMARY ===")
        for k, v in self.final_proxies.items():
            if v:
                with open(OUT_FILES[k], 'w') as f:
                    f.write("\n".join(sorted(v)))
                print(f"[{k.upper()}] Saved {len(v)} unique proxies.")

# Execute
if __name__ == "__main__":
    asyncio.run(StrictProxyCollector().pipeline())
