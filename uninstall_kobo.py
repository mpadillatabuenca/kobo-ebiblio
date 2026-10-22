import os
import shutil
import string


def find_kobo_drive():
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(os.path.join(drive, ".kobo", "version")):
            return drive
    return None


def main():
    kobo = find_kobo_drive()
    if not kobo:
        print("[ERROR] No se ha detectado el Kobo conectado por USB.")
        print("Enchufa el Kobo, pulsa 'Conectar' en su pantalla y vuelve a ejecutar este archivo.")
        return

    print(f"[OK] Kobo detectado en la unidad {kobo}")
    print()

    # 1. Activar el archivo oficial de autodestruccion de NickelMenu
    nm_dir = os.path.join(kobo, ".adds", "nm")
    os.makedirs(nm_dir, exist_ok=True)
    uninstall_flag = os.path.join(nm_dir, "uninstall")
    with open(uninstall_flag, "w") as f:
        pass
    nm_ebiblio = os.path.join(nm_dir, "ebiblio")
    if os.path.exists(nm_ebiblio):
        os.remove(nm_ebiblio)
    print("[OK] Marcado NickelMenu para desinstalacion automatica limpia (.adds\\nm\\uninstall).")

    # 2. Eliminar la carpeta del mod de eBiblio
    ebiblio_dir = os.path.join(kobo, ".adds", "ebiblio")
    if os.path.exists(ebiblio_dir):
        shutil.rmtree(ebiblio_dir, ignore_errors=True)
        print(f"[OK] Eliminada carpeta {ebiblio_dir}")

    # 3. Eliminar cualquier KoboRoot.tgz pendiente si existiese
    koboroot = os.path.join(kobo, ".kobo", "KoboRoot.tgz")
    if os.path.exists(koboroot):
        os.remove(koboroot)
        print(f"[OK] Eliminado {koboroot} pendiente")

    # 4. Asegurar que SSH vuelva a estar en ssh-disabled de fabrica
    ssh_en = os.path.join(kobo, ".kobo", "ssh-enabled")
    ssh_dis = os.path.join(kobo, ".kobo", "ssh-disabled")
    if os.path.exists(ssh_en):
        shutil.move(ssh_en, ssh_dis)
        print("[OK] Restaurado ssh-disabled de fabrica")

    print()
    print("========================================================")
    print("  PROCESO COMPLETADO!")
    print("  Ahora puedes volver a instalar o expulsar el Kobo.")
    print("  Si lo desconectas ahora, NickelMenu se auto-eliminara")
    print("  solo y tu Kobo quedara 100% de fabrica.")
    print("========================================================")


if __name__ == "__main__":
    main()
