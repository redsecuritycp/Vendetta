# Herramienta de Prueba de Carga (Load Testing)

⚠️ **ADVERTENCIA LEGAL IMPORTANTE**

Esta herramienta está diseñada **ÚNICAMENTE** para:
- Pruebas de carga en sistemas propios
- Pruebas autorizadas por escrito en sistemas de terceros
- Evaluación de capacidad de infraestructura propia

**NO utilice esta herramienta para:**
- Atacar sistemas sin autorización
- Realizar ataques DDoS
- Sobrecargar servicios de terceros sin permiso

El uso no autorizado de esta herramienta puede:
- Violar leyes locales, estatales y federales
- Constituir un delito informático
- Resultar en acciones legales

**El usuario es el único responsable del uso de esta herramienta.**

## Instalación

```bash
pip install -r requirements.txt
```

## Configuración

1. Copia `.env.example` a `.env`:
```bash
cp .env.example .env
```

2. Edita `.env` con tus parámetros:
```env
TARGET_URL=https://tu-sitio.com/
MAX_CONCURRENT=600
DURATION_SECONDS=0  # 0 = ilimitado (parar manualmente)
```

## Uso

### Interfaz Gráfica (Recomendado)

Para usar la interfaz gráfica web con Streamlit:

```bash
streamlit run app.py
```

La interfaz se abrirá automáticamente en tu navegador. En Replit, se expone automáticamente y puedes acceder a través de la URL que Replit proporciona.

**Características de la interfaz:**
- Campo para ingresar URL objetivo
- Slider para configurar concurrencia (100-2000)
- Input para duración de la prueba
- Botones para iniciar/detener pruebas
- Gráficos en tiempo real de latencia y RPS
- Estadísticas detalladas
- Reporte final automático

### Línea de Comandos

Para usar desde la línea de comandos:

```bash
python main.py
```

## Parámetros

- `TARGET_URL`: URL objetivo para la prueba de carga
- `MAX_CONCURRENT`: Número máximo de requests concurrentes
- `DURATION_SECONDS`: Duración de la prueba en segundos (0 = ilimitado)

## Resultados

Los resultados se guardan en `results.log` con:
- Total de requests enviados
- Requests exitosos vs errores
- Latencias (mínima, promedio, máxima)
- RPS (Requests por segundo)
- Estadísticas de rendimiento

## Notas

- Aumenta `MAX_CONCURRENT` progresivamente (600 → 800 → 1000)
- Monitorea el sitio objetivo en otra pestaña
- Detén la prueba cuando observes degradación
- Revisa `results.log` para análisis detallado

## Uso en Replit

1. Sube el proyecto a Replit
2. Instala dependencias: `pip install -r requirements.txt`
3. Ejecuta: `streamlit run app.py`
4. Replit detectará automáticamente Streamlit y expondrá el puerto
5. Accede a la URL que Replit proporciona en la pestaña "Webview"
6. Configura los parámetros y haz clic en "Iniciar Prueba"
7. Observa los resultados en tiempo real

