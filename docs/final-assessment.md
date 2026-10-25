# Dictamen final — CC Checker

## Conclusión

**Clasificación: MALWARE, confianza alta.** El comportamiento recuperado del EXE es el de un *crypto-clipper*: vigila el portapapeles Unicode, busca entradas que coincidan con una tabla de destinos de criptomonedas y reescribe el portapapeles cuando el valor calculado cambia. También se copia a una ruta que imita un componente de Windows y se vuelve a lanzar oculto. No encontré evidencia de una función legítima de comprobación de tarjetas en el código desempaquetado.

En sentido estricto, no se ha demostrado autorreplicación; el término técnico respaldado por la evidencia es *malware/clipboard hijacker*, no “virus” autorreplicante.

## Evidencia confirmada

### 1. Sustitución del portapapeles — severidad ALTA

- `FUN_140003c20` llama a `OpenClipboard`, `GetClipboardData(13)` (`CF_UNICODETEXT`) y bloquea el texto con `GlobalLock`.
- El flujo consulta una estructura global de reglas; `FUN_140005e90` recorre la lista y compara cadenas.
- Cuando el texto calculado difiere, el flujo llama a `EmptyClipboard`, asigna memoria y termina con `SetClipboardData(13, ...)`.
- `FUN_140004490` llama a `FUN_140003c20`, conectando esta rutina con el flujo principal.
- `FUN_140001010` inicializa **17 entradas**: 16 valores con etiquetas BTC, LTC, ETH, DOGE, TON, TRX, BCH, ZEC, DASH, XLM, XRP y XMR, además de `STEAMLINK`. No se comprobaron checksums ni titularidad. Las direcciones y los valores de enlace se redactaron del pseudocódigo publicado; el PE reducido de entrada permanece íntegro en el release privado.
- El binario contiene un patrón de URL de oferta de Steam con parámetros `partner` y `token`; no se validó ni utilizó el valor. La entrada `STEAMLINK` sugiere que también puede alterar enlaces de intercambio, aunque no se comprobó su destino en ejecución.

### 2. Copia y relanzamiento oculto — severidad ALTA

- `FUN_140004490` obtiene la ruta del EXE y `%LOCALAPPDATA%`, crea un directorio que contiene `Microsoft\Windows\Credentials\WindowsLogonApplication.exe` y usa `CopyFileA` para copiar el ejecutable allí.
- Luego llama a `CreateProcessA` con la copia como línea de comando y la bandera `0x08000000` (`CREATE_NO_WINDOW`). También crea `Global\WindowsLogonApplicationMutex`.
- `FUN_140004490` oculta la ventana de consola con `ShowWindow(..., 0)`.
- `FUN_140002db0` consulta `TokenElevation`; si no está elevado, usa `ShellExecuteExA` con el verbo `runas` para relanzar el programa y salir.
- No confirmé una clave Run, tarea programada ni otra persistencia tras reinicio; no afirmo que exista.

### 3. Indicador anti-análisis — severidad MEDIA

`FUN_14001bad4` consulta `IsDebuggerPresent` dentro de un flujo de manejo de excepciones. Es un indicador anti-análisis; por sí solo no demuestra evasión completa.

## Contraste con el supuesto “CC Checker”

- El PE desempaquetado y su pseudocódigo no contienen términos de tarjeta/crédito/CVV/CVC ni referencias a Visa, Mastercard, Stripe o PayPal.
- El import table no muestra imports estáticos de WinHTTP, WinINet, Winsock o URLMon; no se observó exfiltración de red en el análisis estático realizado. Esto no descarta carga dinámica u otros flujos en los blobs opacos.
- `CleanControllerImpl.dll` tiene metadatos Malwarebytes CleanController 3.3.0.919 y un certificado incrustado que identifica a Malwarebytes Inc.; **no validé criptográficamente** la firma Authenticode. El EXE principal no lo importa ni contiene su nombre en texto plano, así que no hay evidencia de que lo utilice. Su presencia en el archivo no convierte el paquete en una herramienta legítima.

## Evidencia de entrada e integridad

- Archivo RAR5: 4.427.086 bytes; SHA-256 `a65ffb8b1abe31ff3c7153795180f2b40e82d3ed105b999ae59096c90dc525e3`; `7zz t` informó `Everything is Ok`.
- EXE original: 734.003.200 bytes; SHA-256 `4ca03bb7a95f6a6a2a531094277c440a5dfe167e55b5de3e365e2b72ca5b2962`.
- Los 733.896.704 bytes posteriores al PE eran todos `0x00`, comprobados byte por byte. La copia de entrada reducida no alteró el original: 106.496 bytes; SHA-256 `7eb56e29ec2ed16ed157ddc7e8c2c6c8c839376b0514b795f6d554429ea8fdb1`.
- UPX 5.2.1 verificó la copia (`-t` → `[OK]`) y la desempaquetó como PE32+ x86-64 de 265.216 bytes; SHA-256 `6ffc4ca8f82b7c3a62468208896eaedefcf2bf62f610df7fa20b5498b2ed0034`.
- `CleanControllerImpl.dll`: 9.119.976 bytes; SHA-256 `868b9ae320893804b68bfebe75800f4f589c7836f2120885c8b741fe1fced220`.

## Ejecución y límites

- **No se ejecutó** ningún binario de la muestra; no hubo captura dinámica, tráfico de red ni prueba de la URL/token.
- GitHub Actions no llegó a ejecutar pasos: el run `40159168462` fue bloqueado por facturación/límite de gasto. Evidencia: anotación de GitHub; job terminado en 2 s con cero pasos.
- Como alternativa acotada, Ghidra 12.1.4/JDK 21 descompiló localmente solo el EXE desempaquetado: `openProgram=true`, **766/766 funciones**, 0 fallidas, salida C original de 1.094.625 bytes. Heap limitado a 1,5 GB. El DLL todavía no se ha descompilado.
- `settings.json` y `utils.dll` tienen entropía cercana a 8 bits/byte y siguen sin estructura legible; su contenido/función permanece desconocido.
- El pseudocódigo publicado es una reconstrucción, no el código fuente original. Se redactaron parámetros sensibles, direcciones de billetera y cadenas alfanuméricas largas antes de publicar el C. El PE de entrada del release privado se conserva íntegro para reproducibilidad.

## Recomendación

Tratar el paquete como malware y no ejecutarlo. Si ya se ejecutó en un equipo, aislarlo y revisar el proceso, la ruta de copia bajo `%LOCALAPPDATA%\Microsoft\Windows\Credentials`, el portapapeles y posibles operaciones con billeteras. Si el enlace de Steam pertenece a una cuenta propia, revocar su token de intercambio; no se intentó comprobarlo.