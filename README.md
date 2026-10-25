# CC Checker — análisis privado

Repositorio privado para el análisis estático autorizado del paquete Windows entregado por Marlon. El EXE/DLL no se ejecutan.

## Alcance y estado

- Evidencia inicial: [`docs/initial-triage.md`](docs/initial-triage.md).
- El EXE principal está empaquetado con indicios fuertes de UPX y tiene 733.896.704 bytes finales de relleno cero. La copia PE reducida conserva los 106.496 bytes de imagen; el original queda intacto.
- `CleanControllerImpl.dll` se analiza como componente separado. Sus metadatos lo identifican como Malwarebytes CleanController 3.3.0.919.
- Dictamen actualizado: [`docs/final-assessment.md`](docs/final-assessment.md) — malware tipo *crypto-clipper*; no se observó función útil de comprobación de tarjetas.
- Los binarios objetivo no se versionan en Git. Las copias de entrada y resultados se manejan como assets del release privado `analysis-v1`.

## Reproducir en GitHub Actions

```bash
gh workflow run analyze.yml -R UserZero075/cc-checker-analysis -f release_tag=analysis-v1
```

El workflow valida hashes, prueba/desempaqueta UPX si procede y ejecuta Ghidra headless en `ubuntu-24.04` x86-64 con JDK 21. Incluye preflight del decompilador nativo y contadores de salida.

El dispatch `40159168462` no llegó a ejecutar pasos: GitHub lo bloqueó por facturación/límite de gasto. Como alternativa acotada se descompiló localmente solo el EXE desempaquetado (265.216 bytes): Ghidra abrió el programa y produjo 766/766 funciones, heap limitado a 1,5 GB. El DLL queda pendiente de CI.

**Todos los logs y resultados se suben al release `analysis-v1`**, no a Actions artifacts. El workflow requiere el secret de repositorio `PAT_REPO_TOKEN` para escribir assets en un release privado. El token no se almacena en el repositorio ni en los informes.

## Contenido

- `docs/`: informes humanos y límites de verificación.
- `scripts/`: triage reproducible, sanitización de resultados y script Java de Ghidra.
- `.github/workflows/analyze.yml`: pipeline manual de análisis.

## Límites

La descompilación produce pseudocódigo aproximado, no el código fuente original. El análisis estático no prueba el comportamiento en ejecución. `settings.json` y `utils.dll` no se incluyen en CI: son blobs de alta entropía sin estructura reconocible y no son necesarios para analizar las funciones exportadas del DLL.