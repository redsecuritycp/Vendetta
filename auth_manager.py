"""
Manejo de autenticacion para requests HTTP
Permite configurar cookies, tokens Bearer, basic auth, y headers custom
"""

import requests
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class AuthConfig:
    """Configuracion de autenticacion"""
    auth_type: str = "none"  # none, bearer, basic, cookie, custom_header
    bearer_token: str = ""
    basic_user: str = ""
    basic_pass: str = ""
    cookies: str = ""  # formato: key=value; key2=value2
    custom_headers: str = ""  # formato: Header: Value\nHeader2: Value2

    def apply_to_session(self, session: requests.Session):
        """Aplica la autenticacion a una session de requests"""
        if self.auth_type == "bearer" and self.bearer_token:
            session.headers["Authorization"] = f"Bearer {self.bearer_token}"

        elif self.auth_type == "basic" and self.basic_user:
            session.auth = (self.basic_user, self.basic_pass)

        elif self.auth_type == "cookie" and self.cookies:
            for cookie_pair in self.cookies.split(";"):
                cookie_pair = cookie_pair.strip()
                if "=" in cookie_pair:
                    key, value = cookie_pair.split("=", 1)
                    session.cookies.set(key.strip(), value.strip())

        elif self.auth_type == "custom_header" and self.custom_headers:
            for line in self.custom_headers.strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    session.headers[key.strip()] = value.strip()

    def to_dict(self) -> Dict:
        return {
            "auth_type": self.auth_type,
            "bearer_token": self.bearer_token,
            "basic_user": self.basic_user,
            "cookies": self.cookies,
            "custom_headers": self.custom_headers,
        }


def create_authenticated_session(auth_config: Optional[AuthConfig] = None) -> requests.Session:
    """Crea una session con autenticacion aplicada"""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Vendetta-SecuritySuite/2.0 (Authorized Testing)"
    })
    session.verify = False
    requests.packages.urllib3.disable_warnings()

    if auth_config and auth_config.auth_type != "none":
        auth_config.apply_to_session(session)

    return session
