"""
core/ — Infraestructura compartida de vendetta.

Módulos:
- rate_limiter — SmartRequester + RateLimitConfig + WAFInfo
- auth         — AuthConfig + create_authenticated_session
- url_validator — validate_url, extract_domain, normalize_url

Convención: estos módulos NO importan de `modules/` ni dependen de scanners.
Son la base que el resto del código usa.
"""
