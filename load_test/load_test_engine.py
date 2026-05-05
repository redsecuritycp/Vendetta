"""
Motor de prueba de carga - Lógica refactorizada para uso con interfaz gráfica
"""

import asyncio
import aiohttp
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional
from queue import Queue


class LoadTestEngine:
    """Motor de prueba de carga con control de estado"""
    
    def __init__(self):
        self.is_running = False
        self.should_stop = False
        self.stats = {
            'total_sent': 0,
            'total_completed': 0,
            'successes': 0,
            'errors': 0,
            'latencies': [],
            'start_time': None,
            'elapsed': 0,
            'rps': 0.0
        }
        self.results_queue = Queue()
        self.test_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
    
    async def _fetch(self, session, semaphore, target_url):
        """Realiza un request HTTP"""
        async with semaphore:
            start = time.time()
            try:
                async with session.get(target_url, timeout=20) as resp:
                    latency = time.time() - start
                    result = {
                        'status': resp.status,
                        'latency': latency,
                        'error': None,
                        'timestamp': time.time()
                    }
                    self.results_queue.put(result)
                    return result
            except Exception as e:
                latency = time.time() - start
                result = {
                    'status': None,
                    'latency': latency,
                    'error': str(e)[:100],
                    'timestamp': time.time()
                }
                self.results_queue.put(result)
                return result
    
    async def _run_load_test(self, target_url: str, max_concurrent: int, duration_seconds: int):
        """Ejecuta la prueba de carga de forma asíncrona"""
        semaphore = asyncio.Semaphore(max_concurrent)
        connector = aiohttp.TCPConnector(limit=max_concurrent)
        timeout = aiohttp.ClientTimeout(total=20)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            start_time = time.time()
            tasks = []
            
            while not self.should_stop:
                # Verificar duración si está configurada
                if duration_seconds > 0 and (time.time() - start_time) >= duration_seconds:
                    break
                
                # Crear nuevo task
                task = asyncio.create_task(self._fetch(session, semaphore, target_url))
                tasks.append(task)
                self.stats['total_sent'] += 1
                
                # Pequeño delay para no saturar
                await asyncio.sleep(0)
            
            # Esperar a que terminen los tasks pendientes
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    def _run_in_thread(self, target_url: str, max_concurrent: int, duration_seconds: int):
        """Ejecuta la prueba en un thread separado"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(
                self._run_load_test(target_url, max_concurrent, duration_seconds)
            )
        finally:
            self.loop.close()
            self.is_running = False
    
    def start_test(self, target_url: str, max_concurrent: int = 600, duration_seconds: int = 0):
        """
        Inicia una prueba de carga
        
        Args:
            target_url: URL objetivo
            max_concurrent: Máximo de requests concurrentes
            duration_seconds: Duración en segundos (0 = ilimitado)
        """
        if self.is_running:
            return False
        
        # Resetear estado
        self.is_running = True
        self.should_stop = False
        self.stats = {
            'total_sent': 0,
            'total_completed': 0,
            'successes': 0,
            'errors': 0,
            'latencies': [],
            'start_time': time.time(),
            'elapsed': 0,
            'rps': 0.0
        }
        
        # Iniciar thread
        self.test_thread = threading.Thread(
            target=self._run_in_thread,
            args=(target_url, max_concurrent, duration_seconds),
            daemon=True
        )
        self.test_thread.start()
        
        return True
    
    def stop_test(self):
        """Detiene la prueba de carga"""
        if not self.is_running:
            return False
        
        self.should_stop = True
        
        # Esperar a que termine el thread (máximo 5 segundos)
        if self.test_thread:
            self.test_thread.join(timeout=5.0)
        
        self.is_running = False
        return True
    
    def get_stats(self) -> Dict:
        """
        Obtiene estadísticas actuales de la prueba
        
        Returns:
            Diccionario con estadísticas
        """
        # Procesar resultados pendientes en la cola
        while not self.results_queue.empty():
            try:
                result = self.results_queue.get_nowait()
                self.stats['total_completed'] += 1
                
                if result['status'] == 200:
                    self.stats['successes'] += 1
                else:
                    self.stats['errors'] += 1
                
                if result['latency']:
                    self.stats['latencies'].append(result['latency'])
            except:
                break
        
        # Calcular estadísticas
        if self.stats['start_time']:
            self.stats['elapsed'] = time.time() - self.stats['start_time']
            if self.stats['elapsed'] > 0:
                self.stats['rps'] = self.stats['total_sent'] / self.stats['elapsed']
        
        # Calcular latencias
        latencies = self.stats['latencies']
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        min_lat = min(latencies) if latencies else 0
        max_lat = max(latencies) if latencies else 0
        
        return {
            'is_running': self.is_running,
            'total_sent': self.stats['total_sent'],
            'total_completed': self.stats['total_completed'],
            'successes': self.stats['successes'],
            'errors': self.stats['errors'],
            'elapsed': self.stats['elapsed'],
            'rps': self.stats['rps'],
            'latency_avg': avg_lat,
            'latency_min': min_lat,
            'latency_max': max_lat,
            'latencies': latencies[-100:]  # Últimas 100 para gráficos
        }
    
    def generate_report(self) -> str:
        """
        Genera un reporte final de la prueba
        
        Returns:
            String con el reporte formateado
        """
        stats = self.get_stats()
        
        report = f"""
=== REPORTE FINAL - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===
Duración: {stats['elapsed']:.1f} segundos
Requests enviados: {stats['total_sent']}
Requests completados: {stats['total_completed']}
Éxitos (200 OK): {stats['successes']}
Errores/Timeouts: {stats['errors']}
Latencia mínima: {stats['latency_min']:.3f}s
Latencia promedio: {stats['latency_avg']:.3f}s
Latencia máxima: {stats['latency_max']:.3f}s
RPS aproximado: {stats['rps']:.1f}
"""
        return report

