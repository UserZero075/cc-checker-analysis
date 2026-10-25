# Recurso educativo: análisis defensivo de malware

*Por Marlon Sarduy Machado (UserZero075)*

Este repositorio es un **recurso educativo** para aprender a reconocer y analizar malware de forma defensiva.  
**No es una herramienta ofensiva.** No ejecutes los binarios incluidos fuera de un entorno aislado.

## Advertencia de seguridad

Los archivos aquí almacenados son **malware real**. Su propósito es educativo: que estudiantes, analistas y curiosos puedan entender cómo funcionan los programas maliciosos y cómo protegerse de ellos.

**No ejecutes nada en tu máquina personal.** Usa una máquina virtual aislada, sin conexión a redes sensibles y con permiso explícito.

## Qué encontrarás en este repositorio

- `docs/educational-guide.md` — Guía principal: por qué no descargar programas de Internet, qué es este malware y cómo protegerse.
- `docs/final-assessment.md` — Análisis técnico del comportamiento del malware (crypto-clipper) con evidencia y límites de verificación.
- `analysis/final-assessment.json` — Resumen estructurado del análisis.
- `scripts/` — Herramientas reproducibles para triage de PE, sanitización de salidas y decompilación con Ghidra.
- `.github/workflows/analyze.yml` — Pipeline de análisis estático (requiere GitHub Actions habilitado y facturación válida).
- `release: educational-resource-v1` — Binario original (`CC Checker.exe`, 734 MB) para análisis autorizado. **Advertencia: es malware.**

## Cómo usar este recurso

1. **Lee primero** `docs/educational-guide.md`.
2. **Entiende el riesgo**: el binario es un crypto-clipper. No lo ejecutes.
3. **Si quieres analizar**: hazlo en un entorno aislado, con permiso y sin exponer datos reales.
4. **Verifica hashes**: todos los archivos tienen SHA-256 documentado. Compáralos antes de usarlos.
5. **No compartas** el binario fuera de contextos educativos autorizados.

## Estructura del repositorio

```
docs/
  educational-guide.md    # Guía educativa principal
  final-assessment.md     # Dictamen técnico del malware
analysis/
  final-assessment.json   # Resumen estructurado
scripts/
  triage_pe.py            # Inventario PE (hashes, secciones, imports, exports)
  redact_outputs.py       # Sanitización de secretos y valores sensibles
  summarize_ghidra.py     # Validación de resultados de Ghidra
  DecompileAll.java       # Script Ghidra para decompilación masiva
.github/workflows/
  analyze.yml             # Pipeline CI (bloqueado por facturación en este repo)
```

## Advertencias importantes

- **No ejecutes el binario.** Es malware real.
- **No compartas** el binario sin contexto educativo y autorización.
- **No uses** este material para atacar sistemas ajenos.
- **No confíes** en programas descargados de Internet sin verificar firma y origen.

## Licencia y uso

Este material es para fines educativos y de análisis defensivo. El autor (Marlon Sarduy Machado) no se responsabiliza del uso indebido del binario o del código aquí compartido.

*Un archivo desconocido no es un programa: es un riesgo.*