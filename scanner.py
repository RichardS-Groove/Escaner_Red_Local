#!/usr/bin/env python3
"""
scanner.py — Módulo principal de escaneo de red.
Basado en Advanced-ARP-Scanner (Benjamin, 02/2025).
Extendido con: detección automática Windows/Linux, filtro Ruijie,
hostname resolution, vendor cache, y más.
"""

import os
import re
import json
import socket
import requests
import warnings
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp

warnings.filterwarnings("ignore")

# ─── Vendors de interés especial (router, IoT, etc.) ────────────────────────
ROUTER_VENDORS = ["Ruijie", "TP-Link", "Netgear", "ASUS", "Xiaomi", "D-Link",
                  "Linksys", "Tenda", "Huawei", "ZTE", "Motorola", "Arris",
                  "Cisco", "Ubiquiti", "MikroTik", "Zyxel"]

IOT_VENDORS = ["Ring", "Arlo", "Nest", "Philips", "Eufy", "Sonoff",
               "Wyze", "Tuya", "Shelly", "Tasmota", "Belkin", "WeMo"]

# ─── Vendor cache en memoria ─────────────────────────────────────────────────
_vendor_cache = {}
_CACHE_FILE = os.path.join(os.path.dirname(__file__), "results", "vendor_cache.json")


def _load_vendor_cache():
    global _vendor_cache
    os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, "r") as f:
                _vendor_cache = json.load(f)
        except Exception:
            _vendor_cache = {}


def _save_vendor_cache():
    os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
    try:
        with open(_CACHE_FILE, "w") as f:
            json.dump(_vendor_cache, f, indent=2)
    except Exception:
        pass


_load_vendor_cache()


# ─── Detección automática de subred ─────────────────────────────────────────
def get_local_network():
    """
    Detecta la subred local. Compatible con Windows y Linux/Mac.
    Retorna string CIDR como '192.168.1.0/24' o None si falla.
    """
    import platform
    system = platform.system().lower()

    # Método 1: netifaces (multiplataforma)
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get("addr", "")
                    mask = addr.get("netmask", "")
                    # Excluir loopback y APIPA
                    if ip.startswith("127.") or ip.startswith("169.254"):
                        continue
                    if ip and mask:
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            return str(network)
                        except Exception:
                            continue
    except ImportError:
        pass

    # Método 2: socket fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        pass

    return None


def get_local_interfaces():
    """Retorna lista de interfaces disponibles con su IP."""
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get("addr", "")
                    mask = addr.get("netmask", "")
                    if ip.startswith("127.") or ip.startswith("169.254"):
                        continue
                    if ip and mask:
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            interfaces.append({
                                "interface": iface,
                                "ip": ip,
                                "network": str(network),
                                "mask": mask
                            })
                        except Exception:
                            continue
    except ImportError:
        pass
    return interfaces


# ─── Escaneo ARP principal ───────────────────────────────────────────────────
def scan_network(network, timeout=3, retry=2):
    """
    Envía paquetes ARP a toda la subred y recopila respuestas.
    Intenta con Scapy primero. Si falla o devuelve 0 resultados,
    usa el método nativo de Windows (ping + arp -a) como fallback.
    """
    devices = []

    # ── Método 1: Scapy ARP ──
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=timeout, verbose=0, retry=retry)[0]
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper()
            })
    except Exception as e:
        print(f"[SCAN] Scapy ARP fallo ({e}), usando metodo nativo de Windows...")

    # ── Método 2: Fallback nativo Windows (ping sweep + arp -a) ──
    if len(devices) == 0:
        print(f"[SCAN] Usando fallback nativo: ping sweep + arp -a para {network}")
        devices = _scan_native_windows(network)

    return devices


def _scan_native_windows(network):
    """
    Escaneo nativo de Windows sin Scapy.
    1. Hace ping a cada IP del rango para poblar la tabla ARP del sistema.
    2. Lee la tabla ARP con 'arp -a' y parsea los resultados.
    Funciona siempre, sin drivers adicionales.
    """
    import re
    import platform

    devices = []
    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except Exception as e:
        print(f"[SCAN NATIVE ERROR] Red invalida: {e}")
        return devices

    hosts = list(net.hosts())
    total = len(hosts)
    print(f"[SCAN] Haciendo ping a {total} hosts en {network}...")

    # Ping sweep en paralelo (rápido, solo para llenar la tabla ARP)
    def _ping_one(ip_str):
        try:
            if platform.system().lower() == "windows":
                subprocess.run(
                    ["ping", "-n", "1", "-w", "500", ip_str],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=3, creationflags=0x08000000  # CREATE_NO_WINDOW
                )
            else:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip_str],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=3
                )
        except Exception:
            pass

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(_ping_one, [str(h) for h in hosts])

    print("[SCAN] Ping sweep terminado. Leyendo tabla ARP...")

    # Leer la tabla ARP del sistema operativo
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10,
            creationflags=0x08000000 if platform.system().lower() == "windows" else 0
        )
        arp_output = result.stdout
    except Exception as e:
        print(f"[SCAN NATIVE ERROR] No se pudo leer arp -a: {e}")
        return devices

    # Parsear la salida de arp -a
    # Formato Windows: "  192.168.1.1          d4-31-27-06-91-38     dinámico"
    # Formato Linux:   "? (192.168.1.1) at d4:31:27:06:91:38 [ether] on eth0"
    valid_ips = set(str(h) for h in hosts)

    for line in arp_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Patrón Windows: IP seguida de MAC con guiones
        match_win = re.search(
            r'(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})',
            line
        )
        if match_win:
            ip = match_win.group(1)
            mac = match_win.group(2).upper().replace("-", ":")
            # Solo incluir IPs que están en el rango solicitado
            # y filtrar broadcast (ff:ff:ff:ff:ff:ff)
            if ip in valid_ips and mac != "FF:FF:FF:FF:FF:FF":
                # Evitar duplicados
                if not any(d["ip"] == ip for d in devices):
                    devices.append({"ip": ip, "mac": mac})

    print(f"[SCAN] Encontrados {len(devices)} dispositivos via metodo nativo.")
    return devices


# ─── Vendor lookup (macvendors.com API gratuita) ─────────────────────────────
def get_vendor(mac):
    """
    Busca el fabricante del dispositivo por su MAC.
    Usa cache local + API pública gratuita (sin clave).
    """
    mac_prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    if mac_prefix in _vendor_cache:
        return _vendor_cache[mac_prefix]

    try:
        url = f"https://api.macvendors.com/{mac}"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "EscanerRed/1.0"})
        if resp.status_code == 200:
            vendor = resp.text.strip()
            _vendor_cache[mac_prefix] = vendor
            _save_vendor_cache()
            return vendor
        elif resp.status_code == 404:
            _vendor_cache[mac_prefix] = "Desconocido"
            return "Desconocido"
    except Exception:
        pass

    # Fallback: macaddress.io
    try:
        url2 = f"https://macaddress.io/api?apiKey=at_demo&output=json&search={mac}"
        resp2 = requests.get(url2, timeout=5)
        if resp2.status_code == 200:
            data = resp2.json()
            vendor = data.get("vendorDetails", {}).get("companyName", "Desconocido")
            _vendor_cache[mac_prefix] = vendor
            _save_vendor_cache()
            return vendor
    except Exception:
        pass

    return "Desconocido"


# ─── Hostname resolution ─────────────────────────────────────────────────────
def get_hostname(ip):
    """Intenta resolver el hostname de una IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return ""


# ─── Port scanning ───────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    53: "DNS",
    554: "RTSP",      # Cámaras IP
    9100: "Printer",  # Impresoras
}


def scan_ports(ip, port_list=None, timeout=0.5):
    """
    Escanea puertos comunes en una IP.
    Retorna lista de dicts {port, name, open}.
    """
    if port_list is None:
        port_list = list(COMMON_PORTS.keys())

    open_ports = []
    for port in port_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append({
                        "port": port,
                        "name": COMMON_PORTS.get(port, "Unknown")
                    })
        except Exception:
            pass
    return open_ports


# ─── Clasificación de dispositivo ───────────────────────────────────────────
def classify_device(vendor, open_ports, hostname):
    """Clasifica el tipo de dispositivo basado en vendor + puertos abiertos."""
    vendor_lower = vendor.lower()
    port_nums = [p["port"] for p in open_ports]

    if any(v.lower() in vendor_lower for v in ROUTER_VENDORS):
        return "router"
    if any(v.lower() in vendor_lower for v in IOT_VENDORS):
        return "iot"
    if 554 in port_nums or "cam" in hostname.lower():
        return "camera"
    if 9100 in port_nums or "print" in vendor_lower or "print" in hostname.lower():
        return "printer"
    if 3389 in port_nums or "computer" in hostname.lower():
        return "computer"
    if 80 in port_nums or 443 in port_nums:
        return "server"
    return "unknown"


# ─── Procesamiento en paralelo ───────────────────────────────────────────────
def enrich_devices(devices, max_workers=20, progress_callback=None):
    """
    Enriquece cada dispositivo con vendor, hostname, puertos y clasificación.
    Llama progress_callback(current, total) si se provee.
    """
    total = len(devices)
    completed = [0]

    def enrich_one(device):
        mac = device.get("mac", "")
        ip = device.get("ip", "")
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        ports = scan_ports(ip)
        device_type = classify_device(vendor, ports, hostname)
        result = {
            **device,
            "vendor": vendor,
            "hostname": hostname,
            "open_ports": ports,
            "device_type": device_type,
            "is_router": device_type == "router",
        }
        completed[0] += 1
        if progress_callback:
            progress_callback(completed[0], total)
        return result

    enriched = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enrich_one, d): d for d in devices}
        for future in as_completed(futures):
            try:
                enriched.append(future.result())
            except Exception as e:
                print(f"[ENRICH ERROR] {e}")

    # Ordenar por IP
    enriched.sort(key=lambda x: [int(n) for n in x["ip"].split(".")])
    return enriched


# ─── Export de resultados ─────────────────────────────────────────────────────
def export_json(devices, filepath=None):
    """Guarda los resultados en un archivo JSON."""
    os.makedirs("results", exist_ok=True)
    if filepath is None:
        filepath = "results/devices.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)
    return filepath


def export_csv(devices, filepath=None):
    """Guarda los resultados en un archivo CSV."""
    import csv
    os.makedirs("results", exist_ok=True)
    if filepath is None:
        filepath = "results/devices.csv"
    if not devices:
        return filepath
    fieldnames = ["ip", "mac", "vendor", "hostname", "device_type", "open_ports"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            row = {k: d.get(k, "") for k in fieldnames}
            row["open_ports"] = ", ".join([f"{p['port']}/{p['name']}" for p in d.get("open_ports", [])])
            writer.writerow(row)
    return filepath


# ─── CLI standalone (legado) ──────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("[bold cyan]Escaner de Red — Detección automática[/bold cyan]")

    network = get_local_network()
    if not network:
        console.print("[red]No se pudo detectar la red. Usa el modo manual.[/red]")
        network = input("Rango de red (ej: 192.168.1.0/24): ").strip()

    console.print(f"[green]Red detectada: {network}[/green]")
    devices = scan_network(network)
    console.print(f"[yellow]{len(devices)} dispositivos encontrados. Obteniendo detalles...[/yellow]")

    enriched = enrich_devices(devices)

    table = Table(title="Resultados del Escaneo", show_lines=True)
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Fabricante", style="green")
    table.add_column("Hostname", style="white")
    table.add_column("Tipo", style="yellow")
    table.add_column("Puertos", style="blue")

    for d in enriched:
        ports_str = ", ".join([f"{p['port']}" for p in d.get("open_ports", [])])
        badge = "🌐 ROUTER" if d.get("is_router") else d.get("device_type", "")
        table.add_row(d["ip"], d["mac"], d["vendor"], d.get("hostname", ""), badge, ports_str)

    console.print(table)
    export_json(enriched)
    console.print("[bold green]Resultados guardados en results/devices.json[/bold green]")
