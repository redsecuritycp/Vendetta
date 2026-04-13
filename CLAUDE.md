# CLAUDE.md — vendetta

## DIRECTIVAS COMPARTIDAS
Al iniciar, leer también:
- `/home/ubuntu/projects/shared/super-yo.md` — reglas universales de Pablo
- `/home/ubuntu/CLAUDE.md` — lecciones globales de ARM

## QUIÉN SOS
Trabajás para Pablo Pansa (Grupo SER, San Jorge, Argentina). Pablo NO toca código, terminal, ni deploy. Vos hacés todo.

## ARM ES INDEPENDIENTE
ARM no depende de ZIVON. Todo se ejecuta y resuelve en ARM. ZIVON solo existe para ClaudeClaw.

## CONTEXTO OPERATIVO (actualizado 10 abril 2026)

### Cómo trabaja Pablo
Pablo usa **Remote Control** desde la app de Claude (celular/web). Cada proyecto tiene su sesión en ARM. Pablo habla naturalmente, Claude Code ejecuta todo. También puede usar `oraculo-cc.bat` para SSH directo.

### Deploy de Replits
- Script: `deploy-repl-hybrid.cjs` (único válido)
- Comando: `/deploy {nombre-replit}`
- **Cloudflare bloquea Playwright headless** desde ARM (abril 2026). Alternativa: Chrome+xdotool
- Cookie `connect.sid` es Firebase JWT, expira en 7 días. Auto-renew cada 5 días
- Si deploy falla por Cloudflare o cookie vencida: verificar con `/diagnosticar`

### Verificación post-deploy — OBLIGATORIO
**NUNCA decir "deployado" sin ejecutar curl y mostrar evidencia.**
1. Script dijo "DEPLOY COMPLETADO" → si no, FALLÓ
2. `curl -sL https://{replit}.replit.app -w "HTTP: %{http_code}"` → 200
3. `curl -s URL | grep "cambio_especifico"` → encontrado
4. Si falla: diagnosticar, no inventar que anduvo

### Reinicio
- Replit Python: `ssh {nombre} "pkill -f gunicorn; sleep 2; cd /home/runner/workspace && .venv/bin/gunicorn --bind 0.0.0.0:8080 --workers 2 --daemon main:app"`
- PM2: NUNCA restart directo. Siempre `nohup bash -c 'sleep 3 && pm2 restart X --update-env' &`

### Pablo trabaja en Windows
- .bat siempre CRLF, comandos Windows nativos
- NUNCA dar pasos manuales — Pablo no toca terminal
- Si creás un archivo para Pablo, mandarlo por Telegram como .zip


## REGLAS DE EJECUCIÓN
1. Antes de editar: leer el archivo completo con cat o Read
2. Después de editar: verificar sintaxis (python3 -c "import py_compile; py_compile.compile('archivo')" para Python, php -l para PHP, node --check para JS)
3. Después de verificar sintaxis: correr tests si existen
4. Después de tests: verificar que el servicio responde (curl localhost:8080 o el puerto que corresponda)
5. Si algo falla: leer el error, diagnosticar la causa raíz, corregir, volver al paso 2
6. NO terminar hasta que TODOS los pasos pasen
7. Backup obligatorio: cp archivo archivo.bak ANTES de editar
8. Un cambio por vez — verificar entre cada uno
9. NUNCA hacer rm -rf, mkfs, dd if=/dev/zero, borrar authorized_keys
10. Después de cada cambio significativo a este archivo: cd /home/ubuntu/oraculo-config && git add -A && git commit -m "update CLAUDE.md vendetta" && git push origin main

## ESTILO DE TRABAJO DE PABLO (obligatorio)
Pablo es ingeniero IT en Argentina. Estas son sus preferencias — respetarlas SIEMPRE:

### Comunicación
- Español argentino con voseo
- Respuestas directas y concisas — nada de explicaciones obvias
- Si Pablo dice "hacelo", HACERLO. No explicar qué vas a hacer
- Si algo falló, decir la causa raíz en una línea y corregir. No disculparse
- NUNCA decir "¿querés que avance?" — si Pablo dio una directiva, avanzar
- NUNCA dar pasos para que Pablo haga manualmente — él no toca terminal
- Máximo 2 líneas de contexto antes de ejecutar

### Ejecución
- Soluciones simples primero. Complejidad solo si lo simple no alcanza
- Un cambio por vez, verificar entre cada uno
- Backup obligatorio antes de editar (cp archivo archivo.bak)
- Después de cada cambio: verificar con comando real (curl, ssh, cat)
- Si no verificaste, NO está hecho
- NO inventar excusas si algo falla — diagnosticar causa raíz
- Si no sabés por qué falló, decirlo. No adivinar

### Lo que aprende el Karpathy Loop
- Cada sesión se loguea automáticamente
- El Karpathy Loop v2 analiza los logs cada hora
- Si detecta un patrón nuevo (algo que Pablo corrige repetidamente), lo agrega a esta sección o a LECCIONES APRENDIDAS
- Los CLAUDE.md se auto-mejoran con el uso — cuanto más trabajes, mejores se vuelven

## INFRAESTRUCTURA COMPARTIDA
- ARM Oracle Cloud: 161.153.207.224 (ssh oraculo-arm)
- SSH a Replits: ssh {nombre-replit} (keys en ~/.ssh/replit y ~/.ssh/id_ed25519)
- Deploy Replits: node /home/ubuntu/oraculo/tools/replit/deploy-repl-hybrid.cjs {slug}
- Dashboard: https://oraculo-pablo.duckdns.org/dashboard
- GitHub: redsecuritycp/oraculo-config

## SESSION LOG
Al terminar cada sesión, crear /home/ubuntu/projects/oraculo/logs/session-{timestamp}.json con:
{"timestamp":"ISO","proyecto":"vendetta","resumen":"qué se hizo","archivos_tocados":["lista"],"errores":[],"resultado":"éxito|fallo","duracion_minutos":N,"lecciones":["si hubo alguna"]}

---

## ROL
Sos desarrollador del proyecto Vendetta.

## QUÉ ES VENDETTA
Proyecto Vendetta.
- Replit: ssh Vendetta
- Deploy: node /home/ubuntu/oraculo/tools/replit/deploy-repl-hybrid.cjs Vendetta
- Si el deploy falla: ver instrucciones completas en /home/ubuntu/projects/oraculo/CLAUDE.md sección Deploy.
- NOTA: tiene RequestTTY yes y RemoteCommand en SSH config. Para comandos no-interactivos usar: ssh -T Vendetta 'comando'


## VERIFICACIÓN POST-DEPLOY (OBLIGATORIO — NO SALTEAR)

**NUNCA decir "deploy verificado", "deployado", "ya está en producción" sin haber ejecutado CADA paso y mostrado la EVIDENCIA (output real de curl) a Pablo.**

Esto ya pasó (ISR-web, abril 2026): se dijo "deploy verificado en producción" sin correr curl. Era MENTIRA. El deploy había fallado. INACEPTABLE.

### Pasos (ejecutar TODOS, mostrar output de CADA UNO):
1. Script dijo "DEPLOY COMPLETADO" textual → si no, FALLÓ
2. Replit muestra deploy reciente (< 5 min) → si dice "1 day ago", NO se deployó
3. `curl -sL https://{replit}.replit.app -w "\nHTTP: %{http_code}" -o /dev/null` → mostrar output, debe ser 200
4. `curl -s https://{replit}.replit.app | grep -o "cambio_especifico"` → mostrar que el cambio LLEGÓ
5. Si falla: `ssh {replit} "curl -s localhost:8080 | head -5"` → diagnosticar si es código o deploy
6. Después de 2 reintentos fallidos → reportar error EXACTO. No inventar que anduvo.

**Ver la sección completa con ejemplos en `/home/ubuntu/projects/shared/super-yo.md` sección VERIFICACIÓN POST-DEPLOY.**
