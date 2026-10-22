# Guía de Desinstalación Completa (Volver a Estado 100% de Fábrica)

Este proyecto está diseñado para **no modificar ningún archivo del sistema operativo base del Kobo**. Todo vive aislado en dos carpetas dentro de la memoria USB del Kobo:
* `.adds\ebiblio\` (el sincronizador de eBiblio y tu configuración)
* `.adds\nm\` (el menú ligero **NickelMenu**)

Tienes **3 formas** de quitarlo todo por completo cuando quieras:

---

## Opción 1: Automática en 1 clic desde tu PC (Recomendada)
1. Conecta tu Kobo por USB al ordenador y pulsa **Conectar** en la pantalla del Kobo.
2. Haz doble clic en el archivo **`DESINSTALAR_TODO.bat`** de esta carpeta.
3. Expulsa el Kobo del USB. Al reiniciarse/importar, NickelMenu detectará la orden de desinstalación y se borrará a sí mismo por completo.

---

## Opción 2: Manual desde cualquier ordenador (Sin usar scripts)
Si algún día estás en otro ordenador y no tienes esta carpeta a mano, puedes desinstalarlo a mano desde el Explorador de Archivos en 10 segundos:

1. Conecta el Kobo por USB.
2. Entra en la unidad del Kobo (`KOBOeReader`) y activa **"Ver elementos ocultos"** en el Explorador de Windows.
3. Entra en la carpeta **`.adds`** y **borra la carpeta `ebiblio`**.
4. Entra en la carpeta **`.adds\nm\`**, borra el archivo `ebiblio` y **crea un archivo vacío llamado `uninstall`** (sin extensión `.txt`, solo `uninstall`).
5. Expulsa el Kobo. Al desconectarlo, NickelMenu verá el archivo `uninstall`, borrará su propio módulo (`/usr/local/Kobo/imageformats/libnm.so`) y eliminará la carpeta `.adds\nm`.

---

## Opción 3: ¿Qué pasa con los libros descargados?
Los libros descargados de eBiblio quedan guardados como archivos `.epub` estándar en la carpeta `Digital Editions\` de tu Kobo. Puedes borrarlos como cualquier otro libro desde la propia pantalla del Kobo (manteniendo pulsado el libro -> *Eliminar*) o borrando la carpeta `Digital Editions`.
