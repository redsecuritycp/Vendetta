"""
Rate limiter inteligente con deteccion de WAF y backoff automatico
"""

import time
import random
import requests
from typing import Optional, List
from dataclasses import dataclass, field


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

WAF_SIGNATURES = [
    "cloudflare",
    "akamai",
    "incapsula",
    "imperva",
    "sucuri",
    "aws waf",
    "mod_security",
    "barracuda",
    "f5 big-ip",
    "fortiweb",
]


@dataclass
class RateLimitConfig:
    """Configuracion del rate limiter"""
    requests_per_second: float = 5.0
    max_retries: int = 3
    backoff_factor: float = 2.0
    rotate_user_agent: bool = True
    jitter: bool = True
    proxy: str = ""  # http://host:port o socks5://host:port
    timeout: int = 10


@dataclass
class WAFInfo:
    """Informacion sobre WAF detectado"""
    detected: bool = False
    name: str = ""
    evidence: List[str] = field(default_factory=list)


class SmartRequester:
    """Hace requests con rate limiting, rotacion de UA y backoff"""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.last_request_time = 0.0
        self.consecutive_errors = 0
        self.total_requests = 0
        self.total_retries = 0
        self.waf_info = WAFInfo()

    def _wait(self):
        """Espera el intervalo necesario entre requests"""
        if self.config.requests_per_second <= 0:
            return
        interval = 1.0 / self.config.requests_per_second
        if self.config.jitter:
            interval += random.uniform(0, interval * 0.3)
        # Backoff si hay errores consecutivos
        if self.consecutive_errors > 0:
            interval *= self.config.backoff_factor ** min(self.consecutive_errors, 5)
        elapsed = time.time() - self.last_request_time
        if elapsed < interval:
            time.sleep(interval - elapsed)

    def _get_ua(self) -> str:
        if self.config.rotate_user_agent:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    def _get_proxies(self) -> dict:
        if self.config.proxy:
            return {"http": self.config.proxy, "https": self.config.proxy}
        return {}

    def detect_waf(self, url: str) -> WAFInfo:
        """Detecta si hay un WAF protegiendo el sitio"""
        info = WAFInfo()
        try:
            resp = requests.get(url, timeout=self.config.timeout,
                                headers={"User-Agent": self._get_ua()},
                                verify=False)
            headers_str = str(resp.headers).lower()
            body_lower = resp.text[:5000].lower()
            combined = headers_str + " " + body_lower

            for sig in WAF_SIGNATURES:
                if sig in combined:
                    info.detected = True
                    info.name = sig.title()
                    info.evidence.append(f"Firma detectada: {sig}")

            # Headers tipicos de WAF
            waf_headers = ["cf-ray", "x-sucuri-id", "x-cdn", "x-akamai", "x-waf"]
            for h in waf_headers:
                if h in headers_str:
                    info.detected = True
                    info.evidence.append(f"Header WAF: {h}")

            # Rate limit headers
            if "retry-after" in headers_str or resp.status_code == 429:
                info.detected = True
                info.evidence.append("Rate limiting activo (429 o Retry-After)")

        except Exception:
            pass

        self.waf_info = info
        return info

    def get(self, url: str, session: Optional[requests.Session] = None,
            **kwargs) -> Optional[requests.Response]:
        """GET con rate limiting y retry"""
        return self._request("GET", url, session, **kwargs)

    def _request(self, method: str, url: str,
                 session: Optional[requests.Session] = None,
                 **kwargs) -> Optional[requests.Response]:
        """Request con rate limiting, retry y backoff"""
        self._wait()
        self.total_requests += 1
        self.last_request_time = time.time()

        requester = session or requests
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("headers", {})
        kwargs["headers"]["User-Agent"] = self._get_ua()

        proxies = self._get_proxies()
        if proxies:
            kwargs["proxies"] = proxies

        for attempt in range(self.config.max_retries + 1):
            try:
                resp = requester.request(method, url, **kwargs)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 5))
                    time.sleep(retry_after)
                    self.total_retries += 1
                    continue

                if resp.status_code >= 500:
                    self.consecutive_errors += 1
                    self.total_retries += 1
                    time.sleep(self.config.backoff_factor ** attempt)
                    continue

                self.consecutive_errors = 0
                return resp

            except requests.exceptions.Timeout:
                self.consecutive_errors += 1
                self.total_retries += 1
                if attempt < self.config.max_retries:
                    time.sleep(self.config.backoff_factor ** attempt)
                continue

            except requests.exceptions.ConnectionError:
                self.consecutive_errors += 1
                self.total_retries += 1
                if attempt < self.config.max_retries:
                    time.sleep(self.config.backoff_factor ** (attempt + 1))
                continue

            except Exception:
                self.consecutive_errors += 1
                break

        return None
