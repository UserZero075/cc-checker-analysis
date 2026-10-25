# Guía educativa: por qué no descargues programas así de Internet

*Por Marlon Sarduy Machado (UserZero075)*

## Por qué no debes descargar archivos como este

He subido este binario original a este repositorio privado **solo como recurso educativo**.  
**No lo ejecutes.** No lo compartas. No lo uses para dañar a nadie.

En Internet hay miles de archivos como este. Vienen con nombres inocentes (“CC Checker”, “Cleaner”, “Optimizer”, “Crack”, “Free tool”, etc.) y prometen algo útil. En realidad, muchos son **malware** que roban dinero, credenciales o acceso a cuentas.

## Qué es este programa

El archivo principal (`CC Checker.exe`) es un **crypto-clipper** (hijacker de portapapeles).  
No es un “checker” de tarjetas ni una utilidad legítima. Su propósito es **interceptar y reemplazar direcciones de criptomonedas** que copies al portapapeles, redirigiendo tus pagos a direcciones del atacante.

### Lo que hace el programa (resumen técnico)

- Vigila el portapapeles de Windows (texto Unicode).
- Cuando detecta una dirección de criptomonedas (BTC, LTC, ETH, DOGE, TON, TRX, BCH, ZEC, DASH, XLM, XRP, XMR, etc.), la reemplaza por una dirección controlada por el atacante.
- Se copia a `%LOCALAPPDATA%\Microsoft\Windows\Credentials\WindowsLogonApplication.exe` para intentar pasar desapercibido.
- Se relanza oculto (sin ventana) y puede solicitar elevación de privilegios.
- Incluye una URL fija de Steam con parámetros `partner` y `token`, lo que sugiere intentos de captura de enlaces de intercambio.

### Por qué esto es peligroso

- Si copias una dirección de una billetera para enviar fondos, el programa la cambia por la del atacante. **Pierdes tu dinero.**
- Se disfraza de un componente de Windows para evitar detección.
- Puede elevar privilegios y ocultarse del usuario.
- No tiene función útil real: el nombre “CC Checker” es solo un disfraz.

## Lecciones para usuarios

1. **No descargues ejecutables de fuentes no confiables.** Ni de foros, Telegram, Discord ni enlaces acortados.
2. **Verifica siempre la firma digital** y el origen del software. Si no tiene firma o el nombre del publicador es sospechoso, no lo ejecutes.
3. **Usa una máquina virtual o entorno aislado** si vas a analizar archivos desconocidos.
4. **Mantén un antivirus actualizado**, pero recuerda que el malware moderno a menudo evita la detección tradicional.
5. **Si ya ejecutaste algo similar**, revisa el portapapeles, las rutas de copia y las conexiones de red.

## Sobre este repositorio

Este repositorio contiene:
- El binario original (en la release `educational-resource-v1`) **solo para análisis y aprendizaje**.
- Informes técnicos y hashes para verificación.
- Scripts de análisis reproducible.

**No ejecutes el binario.** Si quieres estudiarlo, hazlo en un entorno aislado y con permiso.

## Nota final

Yo, Marlon, he creado este material para que otros aprendan a reconocer malware y evitar caer en trampas. La ciberseguridad defensiva empieza por no confiar en lo que no conoces.

*Recuerda: un archivo desconocido no es un programa, es un riesgo.*