"""
Interfaz gráfica Streamlit para prueba de carga
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import time
from load_test_engine import LoadTestEngine

# Configuración de página
st.set_page_config(
    page_title="Prueba de Carga",
    page_icon="⚡",
    layout="wide"
)

# Inicializar motor de prueba en session state
if 'engine' not in st.session_state:
    st.session_state.engine = LoadTestEngine()

# Título
st.title("⚡ Herramienta de Prueba de Carga")
st.markdown("---")

# Sidebar con configuración
with st.sidebar:
    st.header("⚙️ Configuración")
    
    target_url = st.text_input(
        "URL Objetivo",
        value="https://diaz.gob.ar/",
        help="URL del sitio a probar"
    )
    
    max_concurrent = st.slider(
        "Concurrencia Máxima",
        min_value=100,
        max_value=2000,
        value=600,
        step=100,
        help="Número máximo de requests concurrentes"
    )
    
    duration_seconds = st.number_input(
        "Duración (segundos)",
        min_value=0,
        value=0,
        help="0 = ilimitado (detener manualmente)"
    )
    
    st.markdown("---")
    
    # Botones de control
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("▶️ Iniciar Prueba", type="primary", use_container_width=True):
            if st.session_state.engine.start_test(target_url, max_concurrent, duration_seconds):
                st.success("Prueba iniciada")
                st.rerun()
            else:
                st.error("La prueba ya está corriendo")
    
    with col2:
        if st.button("⏹️ Detener Prueba", use_container_width=True):
            if st.session_state.engine.stop_test():
                st.warning("Prueba detenida")
                st.rerun()
            else:
                st.info("No hay prueba corriendo")

# Área principal
col1, col2, col3, col4 = st.columns(4)

# Obtener estadísticas
stats = st.session_state.engine.get_stats()

with col1:
    st.metric("Estado", "🟢 Corriendo" if stats['is_running'] else "🔴 Detenido")

with col2:
    st.metric("Requests Enviados", f"{stats['total_sent']:,}")

with col3:
    st.metric("RPS", f"{stats['rps']:.1f}")

with col4:
    st.metric("Tiempo Transcurrido", f"{stats['elapsed']:.1f}s")

st.markdown("---")

# Gráficos
if stats['is_running'] or stats['total_completed'] > 0:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Latencia")
        if stats['latencies']:
            fig_latency = go.Figure()
            fig_latency.add_trace(go.Scatter(
                y=stats['latencies'],
                mode='lines',
                name='Latencia',
                line=dict(color='#1f77b4')
            ))
            fig_latency.update_layout(
                xaxis_title="Request",
                yaxis_title="Latencia (segundos)",
                height=300,
                showlegend=False
            )
            st.plotly_chart(fig_latency, use_container_width=True)
        else:
            st.info("Esperando datos...")
    
    with col2:
        st.subheader("📈 Requests por Segundo")
        if stats['elapsed'] > 0:
            # Calcular RPS en ventanas de tiempo
            rps_data = []
            if stats['total_sent'] > 0:
                current_rps = stats['rps']
                rps_data = [current_rps] * 10  # Últimos 10 puntos
            
            if rps_data:
                fig_rps = go.Figure()
                fig_rps.add_trace(go.Scatter(
                    y=rps_data,
                    mode='lines+markers',
                    name='RPS',
                    line=dict(color='#2ca02c')
                ))
                fig_rps.update_layout(
                    xaxis_title="Tiempo",
                    yaxis_title="RPS",
                    height=300,
                    showlegend=False
                )
                st.plotly_chart(fig_rps, use_container_width=True)
            else:
                st.info("Calculando RPS...")
        else:
            st.info("Esperando datos...")

# Estadísticas detalladas
st.markdown("---")
st.subheader("📋 Estadísticas Detalladas")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("✅ Éxitos (200 OK)", f"{stats['successes']:,}")

with col2:
    st.metric("❌ Errores", f"{stats['errors']:,}")

with col3:
    st.metric("⏱️ Latencia Promedio", f"{stats['latency_avg']:.3f}s")

with col4:
    st.metric("⚡ Latencia Máxima", f"{stats['latency_max']:.3f}s")

# Tabla de estadísticas
st.markdown("---")
st.subheader("📊 Resumen")

stats_data = {
    'Métrica': [
        'Requests Enviados',
        'Requests Completados',
        'Éxitos',
        'Errores',
        'Latencia Mínima',
        'Latencia Promedio',
        'Latencia Máxima',
        'RPS',
        'Tiempo Transcurrido'
    ],
    'Valor': [
        f"{stats['total_sent']:,}",
        f"{stats['total_completed']:,}",
        f"{stats['successes']:,}",
        f"{stats['errors']:,}",
        f"{stats['latency_min']:.3f}s",
        f"{stats['latency_avg']:.3f}s",
        f"{stats['latency_max']:.3f}s",
        f"{stats['rps']:.1f}",
        f"{stats['elapsed']:.1f}s"
    ]
}

st.dataframe(stats_data, use_container_width=True, hide_index=True)

# Reporte final
if not stats['is_running'] and stats['total_completed'] > 0:
    st.markdown("---")
    st.subheader("📄 Reporte Final")
    
    report = st.session_state.engine.generate_report()
    st.code(report, language=None)
    
    if st.button("💾 Guardar Reporte"):
        with open('results.log', 'a') as f:
            f.write(report + '\n' + '='*60 + '\n')
        st.success("Reporte guardado en results.log")

# Auto-refresh cuando está corriendo
if stats['is_running']:
    time.sleep(1)
    st.rerun()

# Advertencia legal
st.markdown("---")
st.warning("""
⚠️ **ADVERTENCIA LEGAL**: Esta herramienta está diseñada únicamente para pruebas autorizadas. 
El uso no autorizado puede violar leyes y resultar en acciones legales.
""")

