# CC Checker — triage estático inicial

## Alcance

Análisis estático del archivo `CC Checker.rar` proporcionado por el usuario, con autorización explícita. El archivo se verificó y extrajo en un directorio temporal; no se ejecutó ningún EXE o DLL. No se conserva la contraseña del archivo en este repositorio.

## Integridad e inventario

- Archivo fuente: RAR5, 4.427.086 bytes; SHA-256 `a65ffb8b1abe31ff3c7153795180f2b40e82d3ed105b999ae59096c90dc525e3`.
- `7zz t` terminó con `Everything is Ok`; 4 ficheros y 744.532.944 bytes declarados sin comprimir.
- `CC Checker.exe`: 734.003.200 bytes; SHA-256 `4ca03bb7a95f6a6a2a531094277c440a5dfe167e55b5de3e365e2b72ca5b2962`.
- `CleanControllerImpl.dll`: 9.119.976 bytes; SHA-256 `868b9ae320893804b68bfebe75800f4f589c7836f2120885c8b741fe1fced220`.
- `settings.json`: 165.844 bytes; SHA-256 `8521700f4958f0b919fb6770584a0bc25b64fda4e347e95d156e9da2a1ee3eb6`.
- `utils.dll`: 1.243.924 bytes; SHA-256 `153db5b04b487099fe45f0a96faa077d2230f0c132ddbedb5334f9bdcb779093`.

## Hallazgos observados

### EXE principal

- PE32+ x86-64, GUI, `SizeOfImage=0x4b000`, 3 secciones; entry RVA `0x48780` cae en `UPX1`.
- `UPX0` declara 192.512 bytes virtuales y cero bytes almacenados; `UPX1` almacena 103.936 bytes y tiene entropía muestreada 7,99. Las secciones `UPX0`/`UPX1` y la cadena `UPX!` indicaban con fuerza empaquetado UPX. La validación posterior con UPX 5.2.1 pasó; véase el dictamen final.
- El final del fichero empieza en el byte 106.496. Se recorrieron los 733.896.704 bytes restantes y todos son `0x00`. La copia reducida `CCChecker-core.exe` conserva los bytes PE anteriores al relleno; SHA-256 `7eb56e29ec2ed16ed157ddc7e8c2c6c8c839376b0514b795f6d554429ea8fdb1`. El EXE original no se modificó.
- Imports estáticos observados: `OpenProcessToken`, `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`, `CoInitializeEx`, `ShellExecuteExA` y `ShowWindow`. Son capacidades importadas; por sí solas no demuestran su uso ni un comportamiento concreto.
- El manifiesto del PE reducido declara `requestedExecutionLevel=asInvoker` y `heapType=SegmentHeap`. El PE no tiene tabla de certificados Authenticode.

### `CleanControllerImpl.dll`

- PE32+ x86-64 nativo, sin directorio CLR ni señales de empaquetado en el triage de secciones.
- Recurso de versión: Company `Malwarebytes`, descripción `CleanController`, versión `3.3.0.919`; manifiesto `asInvoker`.
- El directorio de certificados PE contiene un bloque PKCS#7 cuyo certificado de firma identifica `Malwarebytes Inc` y una cadena DigiCert. Se leyó la identidad del certificado; no se validó el digest Authenticode del fichero ni la confianza de la cadena.
- Exporta 130 símbolos `CCI_*`. Los nombres abarcan ciclo de vida/escaneo/limpieza, historial, cuarentena (consulta, borrado y restauración), reglas de lista blanca, licencia, proxy, callbacks y opciones de recopilación de datos.
- Cadenas relevantes incluyen `https://{0}/unquarantine`, `quarantine`, `unquarantine` y campos de metadatos de detección. El nombre de la API/cadena no prueba por sí solo que el EXE las invoque ni qué datos transmite.
- Evidencia de código en `CCI_SetLicenseState` (RVA `0x5a870`): escribe un DWORD en el objeto de estado global; no permite inferir validación completa de licencia. `CCI_QueueClean` (RVA `0x57350`) delega en una rutina interna y devuelve un booleano. Análisis manual preliminar; falta pseudocódigo Ghidra.

### Archivos opacos

- `settings.json` y `utils.dll` tienen entropía medida de 7,999 y 8,000 bits/byte, comienzan con bytes no estructurados y no exponen texto legible en el triage. Parecen datos comprimidos/cifrados o blobs ofuscados; la causa no está confirmada.

## Riesgo / interpretación

La DLL parece un componente de limpieza de Malwarebytes, pero esto no atribuye el mismo origen o comportamiento al EXE `CC Checker.exe`. El EXE importa carga dinámica y está empaquetado; falta desempaquetarlo y analizar su flujo para conocer su finalidad y si carga ese DLL. Las operaciones de cuarentena/borrado y los setters de proxy son capacidades sensibles, no evidencia de que el ejecutable principal las invoque.

## No verificado

- No se ejecutó el programa; no hubo captura dinámica, tráfico de red ni observación de persistencia.
- No se validó criptográficamente la firma Authenticode del DLL.
- El EXE se validó y desempaquetó con UPX 5.2.1; se obtuvo pseudocódigo Ghidra de la copia de 265.216 bytes (766/766 funciones). El DLL sigue sin decompilarse.
- No se descifraron `settings.json` ni `utils.dll`.
- Los strings/imports del triage inicial son evidencia limitada; el dictamen final añade los call-sites recuperados con Ghidra.

## Estado de CI

`analysis-v1` contiene el PE reducido y el DLL de entrada. El workflow `analyze.yml` está preparado para UPX 5.2.1 y Ghidra 12.2 en `ubuntu-24.04` x86-64, con resultados y logs en releases (sin Actions artifacts). El primer dispatch (`40159168462`) fue bloqueado por facturación/límite de gasto antes de ejecutar pasos; véase [`docs/final-assessment.md`](final-assessment.md).