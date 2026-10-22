import os
import re
import json
import struct
import shutil
import base64
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

COMUNIDADES = [
    ("andalucia", "Andalucía", "https://andalucia.ebiblio.es"),
    ("aragon", "Aragón", "https://aragon.ebiblio.es"),
    ("asturias", "Asturias", "https://asturias.ebiblio.es"),
    ("baleares", "Illes Balears", "https://baleares.ebiblio.es"),
    ("canarias", "Canarias", "https://canarias.ebiblio.es"),
    ("cantabria", "Cantabria", "https://cantabria.ebiblio.es"),
    ("castillalamancha", "Castilla-La Mancha", "https://castillalamancha.ebiblio.es"),
    ("castillayleon", "Castilla y León", "https://castillayleon.ebiblio.es"),
    ("catalunya", "Cataluña", "https://catalunya.ebiblio.es"),
    ("ceuta", "Ceuta", "https://ceuta.ebiblio.es"),
    ("extremadura", "Extremadura", "https://extremadura.ebiblio.es"),
    ("galicia", "Galicia", "https://galicia.ebiblio.es"),
    ("larioja", "La Rioja", "https://larioja.ebiblio.es"),
    ("madrid", "Comunidad de Madrid", "https://madrid.ebiblio.es"),
    ("melilla", "Melilla", "https://melilla.ebiblio.es"),
    ("murcia", "Región de Murcia", "https://murcia.ebiblio.es"),
    ("navarra", "Navarra", "https://navarra.ebiblio.es"),
    ("euskadi", "País Vasco / Euskadi", "https://euskadi.ebiblio.es"),
    ("valencia", "Comunitat Valenciana", "https://valencia.ebiblio.es"),
]

def find_kobo_drive():
    for d in ["D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\"]:
        if os.path.exists(os.path.join(d, ".kobo", "version")):
            return d
    raise RuntimeError("No se detectó el Kobo conectado por USB.")

def extract_adobe_signing_key_from_windows():
    """
    Extrae automáticamente la clave de firma de peticiones ACSM (pkcs12 -> n, d)
    desde la autorización de Adobe Digital Editions en el Registro de Windows.
    """
    import winreg
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    try:
        k_dev = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Adobe\Adept\Device")
        blob_bytes, _ = winreg.QueryValueEx(k_dev, "key")
        user_str, _ = winreg.QueryValueEx(k_dev, "username")
    except OSError:
        raise RuntimeError(
            "No se encontró autorización de Adobe Digital Editions en este PC.\n"
            "Por favor, abre Adobe Digital Editions, pulsa Ctrl+Shift+U e inicia sesión con tu cuenta de Adobe."
        )

    vol_serial = ctypes.wintypes.DWORD()
    ctypes.windll.kernel32.GetVolumeInformationA(b"C:\\", None, 0, ctypes.byref(vol_serial), None, None, None, 0)

    hk_cpu = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
    vendor_id, _ = winreg.QueryValueEx(hk_cpu, "VendorIdentifier")
    ident, _ = winreg.QueryValueEx(hk_cpu, "Identifier")

    m_fam = re.search(r"Family\s+(\d+)", ident)
    m_mod = re.search(r"Model\s+(\d+)", ident)
    m_stp = re.search(r"Stepping\s+(\d+)", ident)
    family = int(m_fam.group(1)) if m_fam else 6
    model = int(m_mod.group(1)) if m_mod else 0
    stepping = int(m_stp.group(1)) if m_stp else 0

    if family >= 15:
        base_fam = 15
        ext_fam = family - 15
    else:
        base_fam = family
        ext_fam = 0
    base_mod = model & 0xF
    ext_mod = (model >> 4) & 0xF
    eax = (ext_fam << 20) | (ext_mod << 16) | (base_fam << 8) | (base_mod << 4) | (stepping & 0xF)
    sig3 = struct.pack(">I", eax)[1:4]

    entropy_bytes = struct.pack(">I12s3s13s", vol_serial.value, vendor_id.encode("ascii")[:12], sig3, user_str.encode("ascii")[:13])

    in_buf = ctypes.create_string_buffer(blob_bytes, len(blob_bytes))
    in_blob = DATA_BLOB(len(blob_bytes), in_buf)
    ent_buf = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes))
    ent_blob = DATA_BLOB(len(entropy_bytes), ent_buf)
    out_blob = DATA_BLOB()

    res = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, ctypes.byref(ent_blob), None, None, 0, ctypes.byref(out_blob)
    )
    if not res:
        raise RuntimeError(f"No se pudo desencriptar la clave DPAPI de ADE (código {ctypes.GetLastError()}).")
    dev_key = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    pass_b64 = base64.b64encode(dev_key).decode("ascii")

    # Localizar pkcs12 en HKCU\Software\Adobe\Adept\Activation
    p12_b64 = None
    k_act = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Adobe\Adept\Activation")
    i = 0
    while True:
        try:
            sub_name = winreg.EnumKey(k_act, i)
            i += 1
            k_sub = winreg.OpenKey(k_act, sub_name)
            j = 0
            while True:
                try:
                    leaf_name = winreg.EnumKey(k_sub, j)
                    j += 1
                    k_leaf = winreg.OpenKey(k_sub, leaf_name)
                    tag_name, _ = winreg.QueryValueEx(k_leaf, "")
                    if tag_name == "pkcs12":
                        p12_b64, _ = winreg.QueryValueEx(k_leaf, "value")
                        break
                except OSError:
                    break
        except OSError:
            break

    if not p12_b64:
        raise RuntimeError("No se encontró el certificado pkcs12 en el registro de Adobe Digital Editions.")

    p12_tmp = os.path.join(BASE_DIR, "_temp_ade.p12")
    pem_tmp = os.path.join(BASE_DIR, "_temp_ade.pem")
    with open(p12_tmp, "wb") as f:
        f.write(base64.b64decode(p12_b64))

    openssl_candidates = [
        r"C:\Program Files\Git\ucrt64\bin\openssl.exe",
        shutil.which("openssl") or "openssl",
    ]
    openssl_bin = next((c for c in openssl_candidates if c and os.path.exists(c)), "openssl")
    cmd = [openssl_bin, "pkcs12", "-in", p12_tmp, "-passin", f"pass:{pass_b64}", "-nodes", "-out", pem_tmp]
    if os.path.exists(r"C:\Program Files\Git\ucrt64\lib\ossl-modules"):
        cmd = [
            openssl_bin, "pkcs12", "-in", p12_tmp, "-passin", f"pass:{pass_b64}",
            "-nodes",
            "-provider-path", r"C:\Program Files\Git\ucrt64\lib\ossl-modules",
            "-provider", "legacy", "-provider", "default",
            "-out", pem_tmp,
        ]
    subprocess.run(cmd, check=True, capture_output=True)
    os.remove(p12_tmp)

    with open(pem_tmp, "r", encoding="utf-8", errors="ignore") as f:
        pem_content = f.read()
    m_cert = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_content, re.S)
    cert_b64 = re.sub(r"\s+", "", m_cert.group(1)) if m_cert else ""

    out_txt = subprocess.check_output([openssl_bin, "rsa", "-in", pem_tmp, "-text", "-noout"]).decode("utf-8")
    os.remove(pem_tmp)

    def get_hex(label):
        m = re.search(label + r":\s+((?:[0-9a-fA-F]{2}:?\s*)+)", out_txt)
        return hex(int(re.sub(r"[^0-9a-fA-F]", "", m.group(1)), 16))

    key_json = {"n": get_hex("modulus"), "d": get_hex("privateExponent"), "cert": cert_b64}
    out_path = os.path.join(BASE_DIR, "adobe_signing_key.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(key_json, f, indent=2)
    print(f"[OK] Extraída automáticamente clave de firma de Adobe en {out_path}")

def ensure_config_json():
    cfg_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
        com_name = next((c[1] for c in COMUNIDADES if c[0] == existing.get("comunidad")), existing.get("comunidad"))
        print(f"[INFO] Cuenta eBiblio actual: {existing.get('ebiblio_user')} ({com_name})")
        try:
            ans = input("Pulsa [Enter] para mantener esta cuenta, o escribe 'c' para cambiarla: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "c":
            return existing

    print("\n--- Configuración de tu cuenta de eBiblio ---")
    for idx, (k, name, url) in enumerate(COMUNIDADES, 1):
        print(f"  {idx:2d}. {name} ({url})")
    choice = input("\nElige el número de tu Comunidad Autónoma [1 para Andalucía]: ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(COMUNIDADES) else 0
    com_key = COMUNIDADES[idx][0]
    user = input("Tu correo/usuario de eBiblio: ").strip()
    pwd = input("Tu contraseña de eBiblio: ").strip()

    cfg = {"comunidad": com_key, "ebiblio_user": user, "ebiblio_pass": pwd}
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"[OK] Guardada configuración en {cfg_path}\n")
    return cfg

def configure_kobo_adobe_page_numbers(kobo):
    conf_path = os.path.join(kobo, ".kobo", "Kobo", "Kobo eReader.conf")
    if not os.path.exists(conf_path):
        return
    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if "showAdobePageNumbers=" in content:
        content = re.sub(r"showAdobePageNumbers=\w+", "showAdobePageNumbers=false", content)
    elif "[Reading]" in content:
        content = content.replace("[Reading]", "[Reading]\nshowAdobePageNumbers=false", 1)
    else:
        content += "\n[Reading]\nshowAdobePageNumbers=false\n"
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Desactivados números de página diminutos en el margen derecho (showAdobePageNumbers=false)")

def install():
    kobo = find_kobo_drive()
    print(f"[OK] Kobo detectado en {kobo}")

    act_xml = os.path.join(kobo, ".adobe-digital-editions", "activation.xml")
    if not os.path.exists(act_xml):
        raise RuntimeError(
            f"El Kobo aún no tiene el archivo {act_xml}.\n"
            "Paso previo necesario (solo 1 vez):\n"
            "  1. Abre Adobe Digital Editions en tu PC.\n"
            "  2. Inicia sesión con tu cuenta de Adobe (Ayuda -> Autorizar equipo).\n"
            "  3. Haz clic en el engranaje junto a 'KOBOeReader' -> 'Autorizar dispositivo'."
        )

    signing_key_path = os.path.join(BASE_DIR, "adobe_signing_key.json")
    need_extract = not os.path.exists(signing_key_path)
    if not need_extract:
        try:
            with open(signing_key_path, "r", encoding="utf-8") as f:
                if not json.load(f).get("cert"):
                    need_extract = True
        except Exception:
            need_extract = True
    if need_extract:
        extract_adobe_signing_key_from_windows()

    cfg = ensure_config_json()
    com_info = next((c for c in COMUNIDADES if c[0] == cfg.get("comunidad")), COMUNIDADES[0])

    ebiblio_dir = os.path.join(kobo, ".adds", "ebiblio")
    nm_dir = os.path.join(kobo, ".adds", "nm")
    nm_already_installed = os.path.exists(os.path.join(nm_dir, "ebiblio")) and not os.path.exists(os.path.join(nm_dir, "uninstall"))
    os.makedirs(ebiblio_dir, exist_ok=True)
    os.makedirs(nm_dir, exist_ok=True)

    uninstall_flag = os.path.join(nm_dir, "uninstall")
    if os.path.exists(uninstall_flag):
        os.remove(uninstall_flag)

    # 1. Copy ARM binary, config.json, and adobe_signing_key.json
    shutil.copy2(os.path.join(BASE_DIR, "ebiblio-kobo"), os.path.join(ebiblio_dir, "ebiblio-kobo"))
    shutil.copy2(os.path.join(BASE_DIR, "config.json"), os.path.join(ebiblio_dir, "config.json"))
    shutil.copy2(signing_key_path, os.path.join(ebiblio_dir, "adobe_signing_key.json"))
    print(f"[OK] Copiados binario ARM y configuración a {ebiblio_dir}")

    # 2. Write sync.sh and start_ui.sh with strict Unix LF (\n) line endings
    sync_sh = (
        "#!/bin/sh\n"
        "mount -o remount,exec /tmp 2>/dev/null\n"
        "if ! cmp -s /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo 2>/dev/null; then\n"
        "    cp -f /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo\n"
        "    chmod +x /tmp/ebiblio-kobo\n"
        "fi\n"
        "/tmp/ebiblio-kobo --sync >/dev/null 2>&1\n"
        "/bin/sync\n"
        "exit 0\n"
    )
    with open(os.path.join(ebiblio_dir, "sync.sh"), "w", encoding="utf-8", newline="\n") as f:
        f.write(sync_sh)

    start_ui_sh = (
        "#!/bin/sh\n"
        "LOG=/mnt/onboard/.adds/ebiblio/ui.log\n"
        "ifconfig lo 127.0.0.1 up 2>/dev/null\n"
        "mount -o remount,exec /tmp 2>/dev/null\n"
        "if ! cmp -s /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo 2>/dev/null; then\n"
        "    killall ebiblio-kobo 2>/dev/null\n"
        "    cp -f /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo\n"
        "    chmod +x /tmp/ebiblio-kobo\n"
        "fi\n"
        "if ! pidof ebiblio-kobo >/dev/null 2>&1; then\n"
        "    /tmp/ebiblio-kobo --addr 127.0.0.1:8686 </dev/null >\"$LOG\" 2>&1 &\n"
        "    sleep 1\n"
        "fi\n"
        "exit 0\n"
    )
    with open(os.path.join(ebiblio_dir, "start_ui.sh"), "w", encoding="utf-8", newline="\n") as f:
        f.write(start_ui_sh)
    print("[OK] Creados scripts sync.sh y start_ui.sh (formato Unix LF)")

    # 3. Write NickelMenu configuration (.adds/nm/ebiblio) with strict Unix LF (\n)
    nm_cfg = (
        "# NickelMenu - Integracion eBiblio para Kobo\n"
        "menu_item : main : Sincronizar eBiblio : nickel_wifi : autoconnect_silent\n"
        "  chain_always : cmd_output : 9999 : quiet : /bin/sh /mnt/onboard/.adds/ebiblio/sync.sh\n"
        "  chain_always : nickel_misc : rescan_books_full\n"
        f"menu_item : main : Catalogo Web ({com_info[1]}) : nickel_wifi : autoconnect\n"
        f"  chain_success : nickel_browser : modal : {com_info[2]}\n"
        "menu_item : main : Ajustes eBiblio : nickel_wifi : autoconnect\n"
        "  chain_success : cmd_output : 5000 : quiet : /bin/sh /mnt/onboard/.adds/ebiblio/start_ui.sh\n"
        "  chain_success : nickel_browser : modal : http://127.0.0.1:8686/\n"
    )
    with open(os.path.join(nm_dir, "ebiblio"), "w", encoding="utf-8", newline="\n") as f:
        f.write(nm_cfg)
    print(f"[OK] Creado menú de NickelMenu en {os.path.join(nm_dir, 'ebiblio')}")

    # 4. Configure Kobo eReader.conf to hide tiny Adobe page numbers
    configure_kobo_adobe_page_numbers(kobo)

    # 5. Copy NickelMenu KoboRoot.tgz into D:\.kobo\KoboRoot.tgz only if not already installed
    nm_tgz = os.path.join(BASE_DIR, "NickelMenu_KoboRoot.tgz")
    if os.path.exists(nm_tgz) and not nm_already_installed:
        shutil.copy2(nm_tgz, os.path.join(kobo, ".kobo", "KoboRoot.tgz"))
        print(f"[OK] Copiado instalador oficial NickelMenu a {os.path.join(kobo, '.kobo', 'KoboRoot.tgz')}")

    # 6. Sincronizar préstamos y portadas HD directamente al Kobo conectado
    exe_path = os.path.join(BASE_DIR, "ebiblio-kobo.exe")
    if os.path.exists(exe_path):
        print("[INFO] Sincronizando préstamos y portadas HD en el Kobo...")
        subprocess.run([exe_path, "--sync"], cwd=BASE_DIR)
        local_state = os.path.join(BASE_DIR, "synced_state.json")
        if os.path.exists(local_state):
            shutil.copy2(local_state, os.path.join(ebiblio_dir, "synced_state.json"))
            os.remove(local_state)

    print("\n[LISTO] Instalación en el Kobo completada con éxito.")

if __name__ == "__main__":
    try:
        install()
    except Exception as e:
        print(f"\n[AVISO] {e}")
