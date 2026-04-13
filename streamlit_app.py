"""
Vendetta Security Suite v2.0
Interfaz grafica Streamlit para pruebas de seguridad autorizadas
"""

import streamlit as st
import plotly.graph_objects as go
import time
import json

from load_test_engine import LoadTestEngine
from sslstrip_sim import SSLStripAnalyzer
from xss_test import XSSAnalyzer
from recon import PassiveRecon
from clickjacking_test import ClickjackingAnalyzer
from exploit_demo import ExploitDemoGenerator
from slowloris import SlowlorisAttacker
from dir_fuzzer import DirectoryFuzzer
from form_analyzer import FormAnalyzer
from subdomain_enum import SubdomainEnumerator
from bypass_403 import Bypass403
from full_scan import FullScanner
from report_generator import ReportGenerator, ScanReport, Finding
from db_manager import DBManager
from template_engine import TemplateEngine, BUILTIN_TEMPLATES
from rate_limiter import SmartRequester, RateLimitConfig
from auth_manager import AuthConfig
from url_validator import validate_url

# --- Iniciar API REST en background ---
try:
    from api_server import start_api_thread
    if "api_started" not in st.session_state:
        start_api_thread(port=8080)
        st.session_state.api_started = True
except Exception:
    pass

# --- Config ---
st.set_page_config(
    page_title="Vendetta Security Suite",
    page_icon="🔥",
    layout="wide"
)

if "engine" not in st.session_state:
    st.session_state.engine = LoadTestEngine()
if "db" not in st.session_state:
    st.session_state.db = DBManager()

db = st.session_state.db

# --- Header ---
st.markdown("""
<div style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); padding: 20px 30px; border-radius: 10px; margin-bottom: 20px;">
    <h1 style="color: #f8fafc; margin: 0; font-size: 28px;">🔥 Vendetta Security Suite <span style="font-size: 14px; color: #94a3b8;">v2.0</span></h1>
    <p style="color: #64748b; margin: 5px 0 0 0;">Suite profesional de auditoria de seguridad web</p>
</div>
""", unsafe_allow_html=True)

st.warning("**ADVERTENCIA LEGAL**: Solo para uso en sistemas propios o con autorizacion explicita.")

# --- Sidebar: Auth & Rate Limit ---
with st.sidebar:
    st.markdown("### Configuracion Global")

    with st.expander("🔐 Autenticacion", expanded=False):
        auth_type = st.selectbox("Tipo", ["none", "bearer", "basic", "cookie", "custom_header"], key="auth_type")
        auth_config = AuthConfig(auth_type=auth_type)
        if auth_type == "bearer":
            auth_config.bearer_token = st.text_input("Token Bearer", type="password", key="bearer_tok")
        elif auth_type == "basic":
            auth_config.basic_user = st.text_input("Usuario", key="basic_user")
            auth_config.basic_pass = st.text_input("Password", type="password", key="basic_pass")
        elif auth_type == "cookie":
            auth_config.cookies = st.text_area("Cookies (key=val; key2=val2)", key="cookies_input", height=80)
        elif auth_type == "custom_header":
            auth_config.custom_headers = st.text_area("Headers (Header: Value)", key="custom_headers", height=80)

    with st.expander("⏱️ Rate Limiting", expanded=False):
        rps = st.slider("Requests/segundo", 1.0, 50.0, 10.0, 0.5, key="rps")
        rotate_ua = st.checkbox("Rotar User-Agent", value=True, key="rotate_ua")
        proxy = st.text_input("Proxy (opcional)", placeholder="socks5://127.0.0.1:9050", key="proxy_input")

    st.markdown("---")
    st.markdown("### API REST")
    st.code("POST /api/scan\nGET  /api/scans\nGET  /api/targets\nPOST /api/templates", language="text")
    st.caption("Puerto 8080")

# --- Tabs ---
tabs = st.tabs([
    "🎯 Full Scan",
    "⚡ Carga",
    "🐌 Slowloris",
    "🔐 HSTS",
    "💉 XSS",
    "🔍 Recon",
    "🖼️ Clickjack",
    "📁 Dirs",
    "📝 Forms",
    "🌐 Subs",
    "💀 PoC",
    "🔓 Bypass403",
    "🧩 Templates",
    "📊 Historial",
])

# =============================================
# TAB 0: FULL SCAN
# =============================================
with tabs[0]:
    st.header("🎯 Escaneo Completo")
    st.markdown("Un boton, un dominio, resultado integral con reporte profesional.")

    col1, col2 = st.columns([2, 1])

    with col1:
        scan_url = st.text_input("URL Objetivo", value="https://ejemplo.com", key="full_scan_url")
        xss_url = st.text_input("URL con parametros para XSS (opcional)", value="", key="full_xss_url",
                                help="Ej: https://ejemplo.com/buscar?q=test")

    with col2:
        st.markdown("**Herramientas a ejecutar:**")
        skip = []
        if not st.checkbox("Reconocimiento", value=True, key="fs_recon"): skip.append("recon")
        if not st.checkbox("HSTS/SSL", value=True, key="fs_hsts"): skip.append("hsts")
        if not st.checkbox("XSS", value=True, key="fs_xss"): skip.append("xss")
        if not st.checkbox("Clickjacking", value=True, key="fs_click"): skip.append("clickjack")
        if not st.checkbox("Dir Fuzzing", value=True, key="fs_dirs"): skip.append("dirs")
        if not st.checkbox("Formularios", value=True, key="fs_forms"): skip.append("forms")
        if not st.checkbox("Subdominios", value=True, key="fs_subs"): skip.append("subs")

    bypass_paths_text = st.text_input("Paths para Bypass 403 (separados por coma)", value="", key="fs_bypass",
                                      help="Ej: .env,wp-config.php,.git/config")
    bypass_paths = [p.strip() for p in bypass_paths_text.split(",") if p.strip()] if bypass_paths_text else None
    if not bypass_paths:
        skip.append("bypass")

    if st.button("🚀 Lanzar Scan Completo", type="primary", key="launch_full_scan", use_container_width=True):
        valid, normalized_url, error = validate_url(scan_url)
        if not valid:
            st.error(f"URL invalida: {error}")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            log_area = st.empty()

            def on_progress(p):
                progress_bar.progress(p.percent / 100)
                status_text.markdown(f"**{p.current_tool}** ({p.current_step}/{p.total_steps})")

            scanner = FullScanner()
            report = scanner.scan(
                normalized_url,
                skip_tools=skip,
                xss_test_url=xss_url or "",
                bypass_paths=bypass_paths,
                on_progress=on_progress,
            )

            progress_bar.progress(1.0)
            status_text.markdown("**Scan completo!**")

            # Mostrar log
            with st.expander("Ver log del scan"):
                for line in scanner.progress.log:
                    st.text(line)

            # Generar reporte
            gen = ReportGenerator()
            html_report = gen.generate_html(report)

            # Guardar en DB
            report._update_summary()
            scan_id = db.save_scan(
                target=normalized_url,
                risk_score=report.get_risk_score(),
                summary=report.summary,
                tools_used=report.tools_used,
                duration=report.duration,
                report_json=report.to_json(),
                report_html=html_report,
            )

            # Resumen visual
            score = report.get_risk_score()
            if score >= 70:
                score_color = "red"
            elif score >= 40:
                score_color = "orange"
            elif score >= 20:
                score_color = "blue"
            else:
                score_color = "green"

            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Risk Score", f"{score}/100")
            with col2:
                st.metric("Criticos", report.summary.get("critico", 0))
            with col3:
                st.metric("Altos", report.summary.get("alto", 0))
            with col4:
                st.metric("Medios", report.summary.get("medio", 0))
            with col5:
                st.metric("Total", len(report.findings))

            # Hallazgos
            if report.findings:
                st.markdown("### Hallazgos")
                for f in report.findings:
                    sev_icons = {"critico": "⛔", "alto": "🔴", "medio": "🟠", "bajo": "🔵", "info": "ℹ️"}
                    icon = sev_icons.get(f.severity, "❓")
                    with st.expander(f"{icon} [{f.severity.upper()}] {f.title} ({f.tool})"):
                        st.markdown(f.description)
                        if f.evidence:
                            st.code(f.evidence, language="text")
                        if f.recommendation:
                            st.success(f"**Recomendacion:** {f.recommendation}")

            # Descargas
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("📥 Descargar Reporte HTML", html_report,
                                   f"vendetta_report_{scan_id}.html", "text/html",
                                   use_container_width=True, type="primary")
            with col2:
                st.download_button("📥 Descargar JSON", report.to_json(),
                                   f"vendetta_report_{scan_id}.json", "application/json",
                                   use_container_width=True)

# =============================================
# TAB 1: CARGA
# =============================================
with tabs[1]:
    st.header("⚡ Prueba de Carga")
    st.markdown("Genera trafico HTTP para evaluar el rendimiento de tu servidor.")

    col1, col2 = st.columns([1, 3])

    with col1:
        st.subheader("Configuracion")

        load_url = st.text_input("URL Objetivo", value="https://ejemplo.com", key="load_url",
                                 help="URL del sitio a probar")
        max_concurrent = st.slider("Concurrencia Maxima", 100, 2000, 600, 100, help="Requests concurrentes")
        duration_seconds = st.number_input("Duracion (segundos)", min_value=0, value=0,
                                           help="0 = ilimitado")

        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("▶️ Iniciar", type="primary", use_container_width=True, key="start_load"):
                if st.session_state.engine.start_test(load_url, max_concurrent, duration_seconds):
                    st.success("Prueba iniciada")
                    st.rerun()
                else:
                    st.error("Ya esta corriendo")
        with col_btn2:
            if st.button("⏹️ Detener", use_container_width=True, key="stop_load"):
                if st.session_state.engine.stop_test():
                    st.warning("Detenida")
                    st.rerun()

    with col2:
        stats = st.session_state.engine.get_stats()

        m1, m2, m3, m4 = st.columns(4)
        with m1: st.metric("Estado", "🟢 Corriendo" if stats["is_running"] else "🔴 Detenido")
        with m2: st.metric("Requests", f"{stats['total_sent']:,}")
        with m3: st.metric("RPS", f"{stats['rps']:.1f}")
        with m4: st.metric("Tiempo", f"{stats['elapsed']:.1f}s")

        if stats["is_running"] or stats["total_completed"] > 0:
            c1, c2 = st.columns(2)
            with c1:
                if stats["latencies"]:
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(y=stats["latencies"], mode="lines", name="Latencia"))
                    fig.update_layout(title="Latencia", height=250, showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)
            with c2:
                st.metric("✅ Exitos", f"{stats['successes']:,}")
                st.metric("❌ Errores", f"{stats['errors']:,}")
                st.metric("⏱️ Latencia Prom.", f"{stats['latency_avg']:.3f}s")

        if stats["is_running"]:
            time.sleep(1)
            st.rerun()

# =============================================
# TAB 2: SLOWLORIS
# =============================================
with tabs[2]:
    st.header("🐌 Slowloris - Ataque Lento")
    st.markdown("Mantiene conexiones HTTP abiertas lentamente, consumiendo recursos del servidor.")

    col1, col2 = st.columns(2)
    with col1:
        slow_url = st.text_input("URL objetivo", value="https://ejemplo.com", key="slow_url")
        slow_sockets = st.slider("Numero de conexiones", 50, 500, 200, key="slow_sockets")
    with col2:
        slow_duration = st.slider("Duracion (segundos)", 10, 120, 30, key="slow_duration")

    if st.button("🐌 Iniciar Slowloris", type="primary", key="start_slowloris"):
        valid, url, err = validate_url(slow_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner(f"Ejecutando Slowloris por {slow_duration}s..."):
                attacker = SlowlorisAttacker()
                result = attacker.analyze(url, slow_sockets, slow_duration)

                col1, col2, col3 = st.columns(3)
                with col1: st.metric("Vulnerable", "⚠️ Si" if result.vulnerable else "✅ No")
                with col2: st.metric("Sockets Creados", result.sockets_created)
                with col3: st.metric("Sockets Vivos", result.sockets_alive)

                if result.details:
                    with st.expander("Ver detalles"):
                        for d in result.details:
                            st.markdown(f"- {d}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations:
                        st.markdown(f"- {r}")

# =============================================
# TAB 3: HSTS
# =============================================
with tabs[3]:
    st.header("🔐 Analisis HSTS/SSLStrip")
    hsts_url = st.text_input("URL a analizar", value="https://ejemplo.com", key="hsts_url")

    if st.button("🔍 Analizar HSTS", type="primary", key="analyze_hsts"):
        valid, url, err = validate_url(hsts_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner("Analizando..."):
                analyzer = SSLStripAnalyzer()
                result = analyzer.analyze(url)

                risk_colors = {"ninguno": "🟢", "bajo": "🟡", "medio": "🟠", "alto": "🔴", "critico": "⛔"}
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("HSTS", "✅ Si" if result.has_hsts else "❌ No")
                with col2: st.metric("Redirige a HTTPS", "✅ Si" if result.redirects_to_https else "❌ No")
                with col3: st.metric("Riesgo", f"{risk_colors.get(result.risk_level, '❓')} {result.risk_level.upper()}")

                if result.has_hsts:
                    st.info(f"**Max-Age:** {result.max_age}s | **Subdominios:** {'Si' if result.include_subdomains else 'No'} | **Preload:** {'Si' if result.preload else 'No'}")
                if result.vulnerabilities:
                    st.error("**Vulnerabilidades:**")
                    for v in result.vulnerabilities: st.markdown(f"- {v}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 4: XSS
# =============================================
with tabs[4]:
    st.header("💉 Prueba de XSS")
    xss_url = st.text_input("URL con parametros", value="https://ejemplo.com/buscar?q=test", key="xss_url",
                            help="La URL debe tener parametros")

    if st.button("🔍 Analizar XSS", type="primary", key="analyze_xss"):
        valid, url, err = validate_url(xss_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner("Probando payloads..."):
                analyzer = XSSAnalyzer()
                result = analyzer.analyze(url)

                risk_colors = {"ninguno": "🟢", "bajo": "🟡", "medio": "🟠", "alto": "🔴", "critico": "⛔", "info": "ℹ️"}
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("Riesgo", f"{risk_colors.get(result.risk_level, '❓')} {result.risk_level.upper()}")
                with col2: st.metric("Params Reflejados", len(result.reflected_params))
                with col3: st.metric("Params Vulnerables", len(result.vulnerable_params))

                if result.reflected_params:
                    st.warning(f"**Parametros que reflejan entrada:** {', '.join(result.reflected_params)}")
                if result.vulnerable_params:
                    st.error("**Vulnerabilidades encontradas:**")
                    for v in result.vulnerable_params:
                        st.markdown(f"- **{v['param']}**: {v['context']} (Severidad: {v['severity']})")
                if result.details:
                    with st.expander("Ver detalles"):
                        for d in result.details: st.markdown(f"- {d}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 5: RECON
# =============================================
with tabs[5]:
    st.header("🔍 Reconocimiento Pasivo")
    recon_url = st.text_input("URL a investigar", value="https://ejemplo.com", key="recon_url")

    if st.button("🔍 Iniciar Reconocimiento", type="primary", key="start_recon"):
        valid, url, err = validate_url(recon_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner("Recopilando informacion..."):
                recon = PassiveRecon()
                result = recon.analyze(url)

                st.subheader(f"Resultados para: {result.domain}")
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**📡 Direcciones IP:**")
                    if result.ip_addresses:
                        for ip in result.ip_addresses: st.code(ip)
                    else: st.text("No encontradas")

                    st.markdown("**🛠️ Tecnologias Detectadas:**")
                    if result.technologies:
                        for tech in result.technologies: st.markdown(f"- {tech}")
                    else: st.text("No detectadas")

                with col2:
                    st.markdown("**🔒 Informacion SSL:**")
                    if result.ssl_info and not result.ssl_info.get("error"):
                        if result.ssl_info.get("issuer"):
                            issuer = result.ssl_info["issuer"].get("organizationName", "Desconocido")
                            st.markdown(f"- **Emisor:** {issuer}")
                        if result.ssl_info.get("notAfter"):
                            st.markdown(f"- **Expira:** {result.ssl_info['notAfter']}")
                        if result.ssl_info.get("protocol"):
                            st.markdown(f"- **Protocolo:** {result.ssl_info['protocol']}")
                    elif result.ssl_info.get("error"):
                        st.error(result.ssl_info["error"])

                st.markdown("---")
                st.markdown(f"**🛡️ Headers de Seguridad:** {len(result.security_headers)}/{len(PassiveRecon.SECURITY_HEADERS)}")

                if result.security_headers:
                    with st.expander("Ver headers presentes"):
                        for header, value in result.security_headers.items():
                            display_val = f"`{value[:80]}...`" if len(value) > 80 else f"`{value}`"
                            st.markdown(f"- **{header}:** {display_val}")
                if result.findings:
                    st.warning("**Hallazgos:**")
                    for f in result.findings: st.markdown(f"- {f}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 6: CLICKJACKING
# =============================================
with tabs[6]:
    st.header("🖼️ Prueba de Clickjacking")
    click_url = st.text_input("URL a verificar", value="https://ejemplo.com", key="click_url")

    if st.button("🔍 Verificar Clickjacking", type="primary", key="check_click"):
        valid, url, err = validate_url(click_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner("Verificando..."):
                analyzer = ClickjackingAnalyzer()
                result = analyzer.analyze(url)

                risk_colors = {"bajo": "🟢", "medio": "🟠", "alto": "🔴"}
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("Vulnerable", "⚠️ Si" if result.vulnerable else "✅ No")
                with col2: st.metric("Puede ser enmarcado", "⚠️ Si" if result.can_be_framed else "✅ No")
                with col3: st.metric("Riesgo", f"{risk_colors.get(result.risk_level, '❓')} {result.risk_level.upper()}")

                col1, col2 = st.columns(2)
                with col1: st.markdown(f"**X-Frame-Options:** `{result.x_frame_options or 'No presente'}`")
                with col2: st.markdown(f"**CSP frame-ancestors:** `{result.csp_frame_ancestors or 'No presente'}`")

                if result.details:
                    with st.expander("Ver detalles"):
                        for d in result.details: st.markdown(f"- {d}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

                st.download_button("📥 Descargar HTML de prueba", result.test_html,
                                   "clickjacking_test.html", "text/html")

# =============================================
# TAB 7: DIRS
# =============================================
with tabs[7]:
    st.header("📁 Fuzzer de Directorios")
    fuzz_url = st.text_input("URL base", value="https://ejemplo.com", key="fuzz_url")

    col1, col2 = st.columns(2)
    with col1:
        fuzz_threads = st.slider("Hilos concurrentes", 5, 30, 10, key="fuzz_threads")
    with col2:
        include_ext = st.checkbox("Incluir extensiones (.bak, .sql, etc)", value=True, key="include_ext")

    import_robots = st.checkbox("📥 Importar paths desde robots.txt", value=False, key="import_robots")
    robots_paths = []
    if import_robots:
        if st.button("🔍 Obtener robots.txt", key="fetch_robots"):
            with st.spinner("Descargando robots.txt..."):
                fuzzer_temp = DirectoryFuzzer()
                robots_paths_found, robots_content = fuzzer_temp.fetch_robots_txt(fuzz_url)
                if robots_content:
                    st.session_state["robots_paths"] = robots_paths_found
                    st.session_state["robots_content"] = robots_content
                    st.success(f"Se encontraron {len(robots_paths_found)} paths")
                else:
                    st.error("No se pudo obtener robots.txt")

        if "robots_content" in st.session_state and st.session_state["robots_content"]:
            with st.expander("Ver contenido de robots.txt"):
                st.code(st.session_state["robots_content"], language="text")
            if "robots_paths" in st.session_state:
                robots_paths = st.session_state["robots_paths"]

    if st.button("📁 Iniciar Fuzzing", type="primary", key="start_fuzz"):
        valid, url, err = validate_url(fuzz_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            custom_paths_to_use = robots_paths if robots_paths else None
            with st.spinner("Buscando archivos expuestos..."):
                fuzzer = DirectoryFuzzer()
                result = fuzzer.analyze(url, custom_paths=custom_paths_to_use, threads=fuzz_threads, include_extensions=include_ext)

                risk_colors = {"ninguno": "🟢", "bajo": "🟡", "medio": "🟠", "alto": "🔴", "critico": "⛔"}
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("Riesgo", f"{risk_colors.get(result.risk_level, '❓')} {result.risk_level.upper()}")
                with col2: st.metric("Paths Probados", result.total_checked)
                with col3: st.metric("Encontrados", len(result.found_paths))

                if result.found_paths:
                    st.warning("**Archivos/Directorios encontrados:**")
                    for path in result.found_paths:
                        risk_icon = {"critico": "⛔", "alto": "🔴", "medio": "🟠", "bajo": "🟡", "info": "ℹ️"}.get(path["risk"], "❓")
                        st.markdown(f"- {risk_icon} **{path['path']}** - Status: {path['status']} ({path['size']} bytes)")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 8: FORMS
# =============================================
with tabs[8]:
    st.header("📝 Analizador de Formularios")
    form_url = st.text_input("URL con formularios", value="https://ejemplo.com/login", key="form_url")

    if st.button("📝 Analizar Formularios", type="primary", key="analyze_forms"):
        valid, url, err = validate_url(form_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            with st.spinner("Analizando formularios..."):
                analyzer = FormAnalyzer()
                result = analyzer.analyze(url)

                risk_colors = {"info": "ℹ️", "bajo": "🟢", "medio": "🟠", "alto": "🔴", "error": "❌"}
                col1, col2 = st.columns(2)
                with col1: st.metric("Riesgo", f"{risk_colors.get(result.overall_risk, '❓')} {result.overall_risk.upper()}")
                with col2: st.metric("Formularios", result.forms_found)

                for i, form in enumerate(result.forms, 1):
                    with st.expander(f"Formulario {i}: {form.method} -> {form.action[:40]}..."):
                        st.markdown(f"**CSRF Token:** {'✅ Presente' if form.has_csrf else '❌ No encontrado'}")
                        st.markdown(f"**Campos:** {len(form.inputs)}")
                        if form.issues:
                            st.error("**Problemas:**")
                            for issue in form.issues: st.markdown(f"- {issue}")
                if result.recommendations:
                    st.success("**Recomendaciones:**")
                    for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 9: SUBS
# =============================================
with tabs[9]:
    st.header("🌐 Enumerador de Subdominios")
    sub_domain = st.text_input("Dominio a enumerar", value="ejemplo.com", key="sub_domain")

    col1, col2 = st.columns(2)
    with col1: sub_threads = st.slider("Hilos concurrentes", 10, 50, 20, key="sub_threads")
    with col2: sub_timeout = st.slider("Timeout (segundos)", 30, 180, 60, key="sub_timeout")

    if st.button("🌐 Buscar Subdominios", type="primary", key="enum_subs"):
        with st.spinner("Buscando subdominios..."):
            enumerator = SubdomainEnumerator()
            result = enumerator.analyze(sub_domain, threads=sub_threads, timeout=sub_timeout)

            col1, col2, col3 = st.columns(3)
            with col1: st.metric("Dominio Base", result.target_domain)
            with col2: st.metric("Probados", result.total_checked)
            with col3: st.metric("Encontrados", len(result.subdomains_found))

            if result.subdomains_found:
                st.info("**Subdominios encontrados:**")
                for sub in result.subdomains_found:
                    http_status = f"HTTP:{sub.http_status or '-'}"
                    https_status = f"HTTPS:{sub.https_status or '-'}"
                    ips = ", ".join(sub.ip_addresses[:2])
                    st.markdown(f"- **{sub.full_domain}** -> {ips} ({http_status}, {https_status})")
                    if sub.title:
                        st.markdown(f"  - Titulo: _{sub.title[:50]}_")
            if result.recommendations:
                st.success("**Recomendaciones:**")
                for r in result.recommendations: st.markdown(f"- {r}")

# =============================================
# TAB 10: PoC
# =============================================
with tabs[10]:
    st.header("💀 Demos de Prueba de Concepto (PoC)")
    st.error("**ADVERTENCIA CRITICA**: Solo usar en TUS PROPIOS sistemas o con autorizacion ESCRITA.")

    demo_type = st.radio("Tipo de demostracion:", ["Defacement Visual", "Clickjacking PoC", "XSS Payloads"], horizontal=True)
    generator = ExploitDemoGenerator()

    if demo_type == "Defacement Visual":
        col1, col2 = st.columns(2)
        with col1:
            defacement_url = st.text_input("URL del sitio vulnerable", value="https://ejemplo.com", key="defacement_url")
            custom_text = st.text_input("Texto a mostrar", value="SITIO VULNERABLE", key="custom_text")
        with col2:
            image_source = st.radio("Fuente de imagen:", ["Subir imagen", "URL de imagen", "Sin imagen"], key="img_source")
            uploaded_image = None
            uploaded_mime = "image/png"
            image_url = None
            if image_source == "Subir imagen":
                uploaded_file = st.file_uploader("Sube una imagen", type=["png", "jpg", "jpeg", "gif", "svg"], key="upload_img")
                if uploaded_file:
                    uploaded_image = uploaded_file.read()
                    uploaded_mime = uploaded_file.type or "image/png"
            elif image_source == "URL de imagen":
                image_url = st.text_input("URL de la imagen", value="", key="img_url")

        if st.button("Generar Demo Defacement", type="primary", key="gen_defacement"):
            html_content = generator.generate_defacement_poc(defacement_url, image_data=uploaded_image,
                                                              image_url=image_url if image_url else None,
                                                              custom_text=custom_text, mime_type=uploaded_mime)
            st.download_button("Descargar HTML de Defacement", html_content,
                               "poc_defacement_visual.html", "text/html", type="primary")

    elif demo_type == "Clickjacking PoC":
        poc_url = st.text_input("URL del sitio", value="https://ejemplo.com", key="poc_url")
        attack_scenario = st.selectbox("Escenario:", [
            ("like_button", "Boton de Like/Follow"),
            ("form_submit", "Envio de formulario"),
            ("delete_account", "Accion destructiva"),
        ], format_func=lambda x: x[1])

        if st.button("Generar Demo Clickjacking", type="primary", key="gen_clickjack"):
            html_content = generator.generate_clickjacking_poc(poc_url, attack_scenario[0])
            st.download_button("Descargar HTML Demo", html_content,
                               "poc_clickjacking_demo.html", "text/html", type="primary")

    else:
        xss_target = st.text_input("URL vulnerable", value="https://ejemplo.com/buscar?q=test", key="xss_target")
        xss_param = st.text_input("Parametro vulnerable", value="q", key="xss_param")

        if st.button("Generar Payloads XSS", type="primary", key="gen_xss"):
            payloads = generator.generate_xss_payloads(xss_target, xss_param)
            st.success(f"Se generaron {len(payloads['payloads'])} payloads")

            for p in payloads["payloads"]:
                with st.expander(f"{p['name']} - {p['impact']}"):
                    st.markdown(f"**Descripcion:** {p['description']}")
                    st.code(p["payload"], language="html")
                    st.text_input("URL con payload:", value=p["full_url"], key=f"url_{p['name']}")

            html_demo = generator.generate_xss_demo_page(xss_target, xss_param)
            st.download_button("Descargar Pagina Demo Completa", html_demo,
                               "poc_xss_demo.html", "text/html", type="primary")

# =============================================
# TAB 11: BYPASS 403
# =============================================
with tabs[11]:
    st.header("🔓 Bypass 403 Forbidden")
    bypass_url = st.text_input("URL base del sitio", value="https://ejemplo.com", key="bypass_url")

    bypass_paths_text = st.text_area("Paths a probar (uno por linea)", value=".env\nwp-config.php\n.git/config\nadmin/",
                                     height=150, key="bypass_paths")

    col1, col2 = st.columns(2)
    with col1:
        try_backups = st.checkbox("🗄️ Variantes backup", value=True, key="try_backups")
        try_encoding = st.checkbox("🔤 URL encoding", value=True, key="try_encoding")
    with col2:
        try_headers = st.checkbox("📨 Headers de bypass", value=True, key="try_headers")
        try_methods = st.checkbox("🔀 Otros metodos HTTP", value=False, key="try_methods")

    if st.button("🔓 Intentar Bypass", type="primary", key="start_bypass"):
        paths_list = [p.strip() for p in bypass_paths_text.strip().split("\n") if p.strip()]
        if not paths_list:
            st.error("Ingresa al menos un path")
        else:
            valid, url, err = validate_url(bypass_url)
            if not valid:
                st.error(f"URL invalida: {err}")
            else:
                with st.spinner(f"Probando bypass en {len(paths_list)} paths..."):
                    bypasser = Bypass403()
                    result = bypasser.analyze(url, paths_list, include_backups=try_backups,
                                              include_encoding=try_encoding, include_headers=try_headers,
                                              include_methods=try_methods)

                    col1, col2, col3 = st.columns(3)
                    with col1: st.metric("Paths Probados", result.paths_tested)
                    with col2: st.metric("Bypasses Encontrados", result.total_bypasses)
                    with col3: st.metric("Duracion", f"{result.duration:.1f}s")

                    if result.total_bypasses > 0:
                        st.success(f"🎯 {result.total_bypasses} bypass exitosos!")
                        for file_info in result.downloadable_files:
                            with st.expander(f"✅ {file_info['original_path']} - {file_info['technique']}"):
                                st.markdown(f"**URL accesible:** `{file_info['bypass_url']}`")
                                st.markdown(f"**Tamanio:** {file_info['size']} bytes")
                                st.code(file_info["content"][:1000] if len(file_info["content"]) > 1000 else file_info["content"])
                                st.download_button(f"📥 Descargar {file_info['original_path']}",
                                                   file_info["content"],
                                                   file_info["original_path"].replace("/", "_") + ".txt",
                                                   "text/plain",
                                                   key=f"dl_{file_info['original_path']}_{file_info['technique']}")
                    else:
                        st.info("No se encontraron bypass. Archivos bien protegidos.")

# =============================================
# TAB 12: TEMPLATES
# =============================================
with tabs[12]:
    st.header("🧩 Motor de Templates")
    st.markdown("Ejecuta checks predefinidos estilo Nuclei contra un objetivo.")

    tmpl_url = st.text_input("URL objetivo", value="https://ejemplo.com", key="tmpl_url")

    st.markdown("**Templates disponibles:**")
    template_options = {t["id"]: f"[{t['severity'].upper()}] {t['name']}" for t in BUILTIN_TEMPLATES}
    selected_templates = st.multiselect("Selecciona templates (vacio = todos)",
                                         options=list(template_options.keys()),
                                         format_func=lambda x: template_options[x],
                                         key="selected_templates")

    with st.expander("➕ Agregar template custom (JSON)"):
        custom_json = st.text_area("Template JSON", height=200, key="custom_template_json",
                                   placeholder='{"id": "my-check", "name": "Mi check", "severity": "medio", "path": "/test", "matchers": [{"type": "status", "values": [200]}]}')

    if st.button("🧩 Ejecutar Templates", type="primary", key="run_templates"):
        valid, url, err = validate_url(tmpl_url)
        if not valid:
            st.error(f"URL invalida: {err}")
        else:
            custom_templates = []
            if custom_json:
                try:
                    parsed = json.loads(custom_json)
                    if isinstance(parsed, list):
                        custom_templates = parsed
                    else:
                        custom_templates = [parsed]
                except json.JSONDecodeError:
                    st.error("JSON invalido en template custom")

            with st.spinner("Ejecutando templates..."):
                engine = TemplateEngine()
                ids = selected_templates if selected_templates else None
                matches = engine.scan(url, custom_templates=custom_templates, template_ids=ids)

                st.metric("Matches", len(matches))

                if matches:
                    for m in matches:
                        sev_icons = {"critico": "⛔", "alto": "🔴", "medio": "🟠", "bajo": "🔵", "info": "ℹ️"}
                        icon = sev_icons.get(m.severity, "❓")
                        with st.expander(f"{icon} [{m.severity.upper()}] {m.template_name}"):
                            st.markdown(f"**ID:** `{m.template_id}`")
                            st.markdown(f"**URL:** `{m.matched_at}`")
                            st.markdown(m.description)
                            if m.evidence:
                                st.code(m.evidence[:500], language="text")
                else:
                    st.success("Ningun template hizo match. Buena senal.")

# =============================================
# TAB 13: HISTORIAL
# =============================================
with tabs[13]:
    st.header("📊 Historial de Scans")

    targets = db.get_targets()

    if targets:
        col1, col2 = st.columns([2, 1])
        with col1:
            filter_target = st.selectbox("Filtrar por objetivo", ["Todos"] + targets, key="hist_filter")
        with col2:
            if st.button("🔄 Refrescar", key="refresh_hist"):
                st.rerun()

        target_filter = None if filter_target == "Todos" else filter_target
        scans = db.get_scans(target=target_filter, limit=30)

        if scans:
            # Tabla de scans
            for scan in scans:
                score = scan["risk_score"]
                if score >= 70: badge = "🔴"
                elif score >= 40: badge = "🟠"
                elif score >= 20: badge = "🔵"
                else: badge = "🟢"

                col1, col2, col3, col4, col5 = st.columns([3, 1, 1, 1, 2])
                with col1: st.markdown(f"**{scan['target']}**")
                with col2: st.markdown(f"{badge} Score: {score}")
                with col3: st.markdown(f"📋 {scan['total_findings']}")
                with col4: st.markdown(f"⏱️ {scan['duration']:.0f}s")
                with col5: st.markdown(f"📅 {scan['scan_date']}")

                # Boton para ver/descargar reporte
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"📥 Reporte HTML #{scan['id']}", key=f"dl_report_{scan['id']}"):
                        full = db.get_scan_report(scan["id"])
                        if full and full.get("report_html"):
                            st.download_button(f"Descargar", full["report_html"],
                                               f"vendetta_report_{scan['id']}.html", "text/html",
                                               key=f"dl_btn_{scan['id']}")
                st.markdown("---")

            # Grafico de evolucion si hay un target seleccionado
            if target_filter and target_filter != "Todos":
                history = db.get_comparison(target_filter)
                if len(history) >= 2:
                    st.subheader("📈 Evolucion del Risk Score")
                    fig = go.Figure()
                    dates = [h["scan_date"] for h in history]
                    scores = [h["risk_score"] for h in history]
                    findings = [h["total_findings"] for h in history]

                    fig.add_trace(go.Scatter(x=dates, y=scores, mode="lines+markers", name="Risk Score",
                                             line=dict(color="#dc2626", width=3)))
                    fig.add_trace(go.Bar(x=dates, y=findings, name="Hallazgos", opacity=0.3,
                                         marker_color="#2563eb"))
                    fig.update_layout(height=300, xaxis_title="Fecha", yaxis_title="Score/Hallazgos",
                                      legend=dict(orientation="h"))
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay scans guardados aun.")
    else:
        st.info("No hay scans guardados. Ejecuta un Full Scan para empezar.")

# --- Footer ---
st.markdown("---")
st.caption("🔥 Vendetta Security Suite v2.0 — Solo para uso autorizado | API REST en puerto 8080")
