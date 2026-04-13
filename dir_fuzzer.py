"""
Directory Fuzzer - Busca archivos y directorios expuestos
Solo para uso en sistemas propios o con autorización explícita
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class FuzzerResult:
    target: str
    found_paths: List[Dict]
    total_checked: int
    duration: float
    risk_level: str
    details: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class DirectoryFuzzer:
    """
    Busca archivos y directorios comunes que podrían estar expuestos
    """
    
    COMMON_PATHS = [
        ".git/config",
        ".git/HEAD",
        ".gitignore",
        ".env",
        ".env.local",
        ".env.production",
        ".htaccess",
        ".htpasswd",
        ".svn/entries",
        ".DS_Store",
        "robots.txt",
        "sitemap.xml",
        "crossdomain.xml",
        "security.txt",
        ".well-known/security.txt",
        "admin/",
        "administrator/",
        "admin.php",
        "admin.html",
        "login/",
        "login.php",
        "wp-admin/",
        "wp-login.php",
        "wp-config.php",
        "wp-config.php.bak",
        "config.php",
        "config.php.bak",
        "configuration.php",
        "settings.php",
        "database.yml",
        "config/database.yml",
        "config.yml",
        "config.json",
        "package.json",
        "composer.json",
        "Gemfile",
        "requirements.txt",
        "backup/",
        "backups/",
        "backup.sql",
        "backup.zip",
        "backup.tar.gz",
        "db.sql",
        "database.sql",
        "dump.sql",
        "test/",
        "tests/",
        "debug/",
        "debug.log",
        "error.log",
        "access.log",
        "logs/",
        "log/",
        "tmp/",
        "temp/",
        "cache/",
        "uploads/",
        "files/",
        "images/",
        "assets/",
        "static/",
        "api/",
        "api/v1/",
        "api/v2/",
        "swagger/",
        "swagger.json",
        "api-docs/",
        "graphql",
        "graphiql",
        "phpmyadmin/",
        "phpinfo.php",
        "info.php",
        "server-status",
        "server-info",
        ".bash_history",
        ".ssh/",
        "id_rsa",
        "id_rsa.pub",
        "web.config",
        "readme.txt",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "VERSION",
        "install/",
        "setup/",
        "cgi-bin/",
        "scripts/",
        "includes/",
        "vendor/",
        "node_modules/",
        ".vscode/",
        ".idea/",
    ]
    
    SENSITIVE_EXTENSIONS = [
        ".bak", ".backup", ".old", ".orig", ".save",
        ".sql", ".db", ".sqlite", ".mdb",
        ".log", ".txt",
        ".zip", ".tar", ".gz", ".rar",
        ".conf", ".config", ".ini", ".yml", ".yaml", ".json",
        ".key", ".pem", ".crt", ".p12"
    ]
    
    RISK_LEVELS = {
        ".git": "critico",
        ".env": "critico",
        "id_rsa": "critico",
        ".ssh": "critico",
        "backup.sql": "critico",
        "wp-config": "alto",
        "config.php": "alto",
        "database": "alto",
        "admin": "medio",
        "phpmyadmin": "medio",
        "phpinfo": "medio",
        "debug": "medio",
        "log": "bajo",
        "robots.txt": "info",
        "sitemap": "info"
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def _get_risk_level(self, path: str) -> str:
        """Determina el nivel de riesgo de un path encontrado"""
        path_lower = path.lower()
        for keyword, level in self.RISK_LEVELS.items():
            if keyword in path_lower:
                return level
        return "info"
    
    def fetch_robots_txt(self, url: str) -> Tuple[List[str], str]:
        """
        Descarga y parsea robots.txt para extraer paths
        
        Returns:
            Tuple con (lista de paths, contenido raw del robots.txt)
        """
        if not url.endswith("/"):
            url += "/"
        
        robots_url = urljoin(url, "robots.txt")
        paths = []
        content = ""
        
        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                content = response.text
                for line in content.split("\n"):
                    line = line.strip()
                    if "#" in line:
                        line = line.split("#")[0].strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            path = path.lstrip("/")
                            if path.endswith("$"):
                                path = path[:-1]
                            if "*" not in path and path:
                                paths.append(path)
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            path = path.lstrip("/")
                            if path.endswith("$"):
                                path = path[:-1]
                            if "*" not in path and path:
                                paths.append(path)
        except Exception:
            pass
        
        return list(set(paths)), content
    
    def _check_path(self, base_url: str, path: str) -> Optional[Dict]:
        """Verifica si un path existe y retorna información"""
        try:
            url = urljoin(base_url, path)
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            if response.status_code in [200, 301, 302, 403]:
                content_length = len(response.content)
                content_type = response.headers.get("Content-Type", "unknown")
                
                is_interesting = True
                if response.status_code == 200:
                    if content_length < 100 and "text/html" in content_type.lower():
                        if "404" in response.text.lower() or "not found" in response.text.lower():
                            is_interesting = False
                
                if is_interesting:
                    return {
                        "path": path,
                        "url": url,
                        "status": response.status_code,
                        "size": content_length,
                        "content_type": content_type,
                        "risk": self._get_risk_level(path)
                    }
            
            return None
            
        except Exception:
            return None
    
    def analyze(self, url: str, custom_paths: Optional[List[str]] = None, 
                threads: int = 10, include_extensions: bool = True) -> FuzzerResult:
        """
        Ejecuta el fuzzing de directorios
        
        Args:
            url: URL base del objetivo
            custom_paths: Lista adicional de paths a probar
            threads: Número de hilos concurrentes
            include_extensions: Incluir pruebas con extensiones sensibles
        """
        if not url.endswith("/"):
            url += "/"
        
        paths_to_check = list(self.COMMON_PATHS)
        
        if custom_paths:
            paths_to_check.extend(custom_paths)
        
        if include_extensions:
            base_files = ["index", "config", "settings", "database", "backup", "admin"]
            for base in base_files:
                for ext in self.SENSITIVE_EXTENSIONS:
                    paths_to_check.append(f"{base}{ext}")
        
        paths_to_check = list(set(paths_to_check))
        
        found_paths = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_path, url, path): path 
                for path in paths_to_check
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)
        
        duration = time.time() - start_time
        
        found_paths.sort(key=lambda x: (
            {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}.get(x["risk"], 5),
            x["path"]
        ))
        
        if any(p["risk"] == "critico" for p in found_paths):
            risk_level = "critico"
        elif any(p["risk"] == "alto" for p in found_paths):
            risk_level = "alto"
        elif any(p["risk"] == "medio" for p in found_paths):
            risk_level = "medio"
        elif found_paths:
            risk_level = "bajo"
        else:
            risk_level = "ninguno"
        
        details = [
            f"URL objetivo: {url}",
            f"Paths probados: {len(paths_to_check)}",
            f"Paths encontrados: {len(found_paths)}",
            f"Duración: {duration:.1f}s"
        ]
        
        recommendations = []
        if risk_level in ["critico", "alto"]:
            recommendations.append("Se encontraron archivos sensibles expuestos")
            recommendations.append("Bloquear acceso a archivos de configuración (.env, config.php)")
            recommendations.append("Eliminar archivos de backup del servidor público")
            recommendations.append("Bloquear acceso a directorios .git, .svn")
            recommendations.append("Revisar permisos de archivos y directorios")
        elif risk_level == "medio":
            recommendations.append("Se encontraron rutas administrativas expuestas")
            recommendations.append("Considerar restringir acceso por IP a paneles admin")
            recommendations.append("Implementar autenticación fuerte")
        else:
            recommendations.append("No se encontraron archivos críticos expuestos")
            recommendations.append("Mantener buenas prácticas de seguridad")
        
        return FuzzerResult(
            target=url,
            found_paths=found_paths,
            total_checked=len(paths_to_check),
            duration=duration,
            risk_level=risk_level,
            details=details,
            recommendations=recommendations
        )


def main():
    import sys
    
    print("=" * 60)
    print("DIRECTORY FUZZER - Búsqueda de Archivos Expuestos")
    print("=" * 60)
    print("\nADVERTENCIA: Solo para sistemas propios o autorizados")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python dir_fuzzer.py <url>")
        print("Ejemplo: python dir_fuzzer.py https://mi-sitio.com")
        sys.exit(1)
    
    url = sys.argv[1]
    
    fuzzer = DirectoryFuzzer()
    result = fuzzer.analyze(url)
    
    print(f"\nRiesgo: {result.risk_level.upper()}")
    print(f"Encontrados: {len(result.found_paths)} paths")
    
    for path in result.found_paths:
        print(f"  [{path['risk'].upper()}] {path['path']} - {path['status']}")


if __name__ == "__main__":
    main()
