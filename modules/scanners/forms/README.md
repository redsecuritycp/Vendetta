# scanners/forms

Analizador de formularios HTML. Inspecciona cada `<form>` de una URL y reporta
problemas de seguridad: token CSRF ausente, campos sensibles mal tipados,
login sobre HTTP, autocomplete activo en campos password, falta de validación
HTML5, método GET con contraseña, etc.

## Qué hace

1. `GET` la URL, parsea con BeautifulSoup, encuentra todos los `<form>`.
2. Por cada form: extrae `action`, `method` y los `<input>/<textarea>/<select>`.
3. Detecta token CSRF por nombre (lista `CSRF_TOKEN_NAMES`: `csrf`,
   `csrftoken`, `csrfmiddlewaretoken`, `_token`, `authenticity_token`,
   `xsrf`, `__requestverificationtoken`, etc.) o meta-tag CSRF.
4. Analiza inputs: password con autocomplete, campos sensibles
   (`password`, `cvv`, `ssn`, `api_key`...) que no son `password`/`hidden`,
   emails sin `pattern` ni `required`.
5. Asigna `risk_level` por form (`alto` si falta CSRF, `medio` si hay
   problemas de password, `bajo` si solo issues menores).
6. Consolida `overall_risk` del target y arma `recommendations`.

## Interfaz pública

```python
from modules.scanners.forms import FormAnalyzer, FormAnalyzerResult, FormInfo

analyzer = FormAnalyzer()
result: FormAnalyzerResult = analyzer.analyze("https://target.com/login")

print(result.overall_risk)   # 'alto' | 'medio' | 'bajo' | 'info' | 'error'
print(result.forms_found)    # int
for form in result.forms:
    print(form.method, form.action, form.has_csrf, form.risk_level)
    for issue in form.issues:
        print("  -", issue)
print(result.recommendations)
```

## Dependencias

- `requests`
- `beautifulsoup4`
- stdlib: `dataclasses`, `typing`, `urllib.parse`, `re`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.forms.scanner 'https://ejemplo.com/login'
# o vía wrapper compat:
python form_analyzer.py 'https://ejemplo.com/login'
```

## Retro-compatibilidad

`form_analyzer.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 5 (2026-05-14) salvo que algún
consumer externo lo siga importando.

Imports flat soportados:

```python
from form_analyzer import FormAnalyzer
from form_analyzer import FormAnalyzer, FormAnalyzerResult, FormInfo
```

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real →
`raw_results.forms` debe traer `forms_found >= 0` y un `overall_risk`
distinto a `error`.

## Cómo desinstalar / desactivar

Pasar `skip_tools=["forms"]` al `POST /api/scan`, o comentar el paso en
`full_scan.py` (futuro: `modules/scan_orchestrator/orchestrator.py`).
