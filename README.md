# kobo-ebiblio

Integración nativa de **eBiblio** (bibliotecas públicas de España) para lectores **Kobo** (Kobo Clara Colour, Libra Colour, Clara BW, Clara 2E, etc.) usando el lector original de fábrica (*Nickel*) sin necesidad de instalar KOReader ni usar el ordenador para cada préstamo.

## ¿Qué hace exactamente?

En España, los lectores Kobo no traen integración directa con **eBiblio** por Wi-Fi (a diferencia de Vivlio o PocketBook), obligando normalmente a descargar el archivo `.acsm` en un PC, abrirlo con Adobe Digital Editions y pasarlo por cable USB al Kobo.

**`kobo-ebiblio`** añade un menú nativo en la pantalla de inicio del Kobo mediante **NickelMenu** con 3 funciones:
1. **`Sincronizar eBiblio` (1 clic):** Abre una ventana con indicador de progreso que se conecta por Wi-Fi a tu cuenta de eBiblio (en cualquiera de las 19 Comunidades/Ciudades Autónomas), detecta tus préstamos activos en `/my_profile/activity`, descarga el ticket `.acsm`, lo canjea con los servidores de Adobe manteniendo su licencia oficial (`META-INF/rights.xml` y `<loanToken>` en `.adobe-digital-editions/activation.xml`), guarda el `.epub` en `Digital Editions/` y actualiza tu biblioteca (limpiando además los préstamos que ya hayas devuelto o hayan caducado).
2. **`Catálogo Web (<Comunidad>)`:** Abre el navegador integrado del Kobo en el portal eBiblio de tu comunidad por si quieres pedir un préstamo directamente desde el Kobo (también puedes pedir el préstamo desde la app de eBiblio de tu móvil y luego pulsar *Sincronizar eBiblio* en el Kobo).
3. **`Ajustes eBiblio`:** Abre una interfaz local adaptada a tinta electrónica (`http://127.0.0.1:8686`) para elegir tu Comunidad Autónoma y guardar tu usuario/contraseña de eBiblio. Se apaga sola tras unos minutos de inactividad para no consumir batería en segundo plano.

---

## Estructura del Proyecto

* [`cmd/ebiblio-kobo/main.go`](cmd/ebiblio-kobo/main.go): Código fuente en Go (cero dependencias externas) que compila a un único binario estático para el procesador ARM del Kobo (`ebiblio-kobo`) y para Windows (`ebiblio-kobo.exe`).
* [`setup_kobo.py`](setup_kobo.py) / [`INSTALAR_EN_KOBO.bat`](INSTALAR_EN_KOBO.bat): Instalador automático en el Kobo por USB.
* [`uninstall_kobo.py`](uninstall_kobo.py) / [`DESINSTALAR_TODO.bat`](DESINSTALAR_TODO.bat) / [`COMO_DESINSTALAR.md`](COMO_DESINSTALAR.md): Desinstalador completo en 1 clic para dejar el Kobo 100% de fábrica.

---

## Paso 0: Autorización inicial con Adobe Digital Editions (Solo 1 vez en la vida)

Para que el motor nativo del Kobo (`librmsdk.so`) pueda abrir los préstamos de eBiblio y el mod pueda canjear los tickets `.acsm` por Wi-Fi en tu nombre, es necesario hacer una única vez la autorización oficial de Adobe en el ordenador:

1. **Instala [Adobe Digital Editions (ADE)](https://www.adobe.com/es/solutions/ebook/digital-editions/download.html)** en tu PC con Windows.
2. **Autoriza tu ordenador en ADE:** Abre Adobe Digital Editions y ve a **Ayuda → Autorizar equipo...** (`Ctrl+Shift+U`). Introduce tu **Adobe ID** (correo y contraseña de Adobe).
3. **Autoriza el Kobo en ADE:** Conecta tu Kobo por USB al ordenador. En la columna izquierda de ADE aparecerá **`KOBOeReader`**. Haz clic en el icono del **engranaje ⚙️** junto a `KOBOeReader` y selecciona **«Autorizar dispositivo...»**.
   - Esto crea el archivo oficial `.adobe-digital-editions/activation.xml` dentro de tu Kobo con tu identificador de usuario (`adept:user`).

> **Nota:** Nuestro instalador (`INSTALAR_EN_KOBO.bat` / `setup_kobo.py`) comprueba automáticamente que tu Kobo tenga `activation.xml` y extrae de forma transparente tu clave de firma (`adobe_signing_key.json`) desde la autorización de Adobe Digital Editions de tu PC para copiarla al Kobo. **Una vez hecho esto la primera vez, no volverás a necesitar abrir Adobe Digital Editions ni conectar el Kobo al PC para pedir libros.**

---

## Instalación en el Kobo

1. Conecta tu Kobo por USB al ordenador y pulsa **Conectar** en la pantalla del Kobo.
2. Ejecuta **`INSTALAR_EN_KOBO.bat`** (o `python setup_kobo.py`).
   - El script verificará que el Paso 0 esté completado, extraerá `adobe_signing_key.json` automáticamente si no existe, instalará el binario ARM en `.adds/ebiblio/` y configurará **NickelMenu**.
3. Expulsa el Kobo de forma segura en Windows y desconecta el cable USB. El Kobo se reiniciará brevemente para activar **NickelMenu** y verás el nuevo botón en la esquina inferior derecha de la pantalla principal.

---

## Cómo Desinstalarlo Todo (Volver al Kobo 100% de fábrica)

Consulta [`COMO_DESINSTALAR.md`](COMO_DESINSTALAR.md) o simplemente conecta el Kobo por USB y haz doble clic en **`DESINSTALAR_TODO.bat`**.

---

## Compilar desde el código fuente

```powershell
# Compilar para Windows (pruebas en PC)
$env:CGO_ENABLED="0"
go build -ldflags="-s -w" -o ebiblio-kobo.exe ./cmd/ebiblio-kobo

# Compilar binario estático Linux ARMv7 para Kobo
$env:GOOS="linux"; $env:GOARCH="arm"; $env:GOARM="7"; $env:CGO_ENABLED="0"
go build -ldflags="-s -w" -o ebiblio-kobo ./cmd/ebiblio-kobo
```
