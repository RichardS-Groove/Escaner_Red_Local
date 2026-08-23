#!/usr/bin/env python3
"""
run.py — Lanzador unificado del Escáner de Red.
Verifica dependencias, permisos de admin, y abre el navegador automáticamente.
"""

import sys
import os
import time
import ctypes
import platform
import subprocess
import webbrowser
import threading

HOST = "localhost"
PORT = 5050
URL  = f"http://{HOST}:{PORT}"

# ─── Verificar permisos de administrador (Windows) ───────────────────────────
def is_admin():
    system = platform.system().lower()
    if system == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def request_admin():
    """Reinicia el proceso con privilegios de administrador (Windows)."""
    if platform.system().lower() == "windows":
        print("[!] Solicitando permisos de administrador...")
        script = os.path.abspath(sys.argv[0])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}"', None, 1
        )
        if ret <= 32:
            print("[ERROR] No se pudieron obtener permisos de administrador.")
            print("        Ejecuta manualmente como Administrador.")
        sys.exit(0)


# ─── Verificar e instalar dependencias ───────────────────────────────────────
def check_dependencies():
    required = ["flask", "flask_cors", "scapy", "netifaces", "requests", "rich"]
    missing = []
    for mod in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)

    if missing:
        print(f"[!] Instalando dependencias faltantes: {missing}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-q",
            "flask", "flask-cors", "scapy", "netifaces", "requests", "rich", "python-nmap"
        ])
        print("[✓] Dependencias instaladas.")


# ─── Abrir navegador cuando el servidor esté listo ───────────────────────────
def open_browser_when_ready():
    """Espera que el servidor responda y abre el navegador."""
    import urllib.request
    for _ in range(30):
        time.sleep(1)
        try:
            urllib.request.urlopen(URL, timeout=1)
            webbrowser.open(URL)
            print(f"\n[✓] Navegador abierto en {URL}")
            return
        except Exception:
            pass
    print(f"\n[!] No se pudo abrir el navegador. Abre manualmente: {URL}")


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("   🌐  Escáner de Red Local — Ruijie & Network Discovery")
    print("=" * 60)

    # Verificar admin
    if not is_admin():
        print("\n[⚠] ATENCIÓN: Se necesitan permisos de Administrador")
        print("    para enviar paquetes ARP y escanear la red.\n")
        if platform.system().lower() == "windows":
            choice = input("¿Deseas reiniciar como Administrador? (s/n): ").strip().lower()
            if choice == "s":
                request_admin()
        else:
            print("    Ejecuta con: sudo python run.py\n")
            sys.exit(1)

    # Verificar dependencias
    print("\n[→] Verificando dependencias...")
    check_dependencies()
    print("[✓] Todo OK\n")

    # Cambiar al directorio del script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Abrir navegador en background
    browser_thread = threading.Thread(target=open_browser_when_ready, daemon=True)
    browser_thread.start()

    print(f"[→] Iniciando servidor en {URL}")
    print("    Presiona CTRL+C para detener.\n")

    # Importar y correr Flask
    from api import app
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[✓] Servidor detenido. ¡Hasta luego!")
