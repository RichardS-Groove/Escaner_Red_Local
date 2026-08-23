#!/usr/bin/env python3
"""
api.py — Servidor Flask REST API para el Escáner de Red.
Expone endpoints para lanzar escaneos, obtener resultados en tiempo real
y exportar datos.
"""

import os
import json
import time
import threading
from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS
from scanner import (
    get_local_network,
    get_local_interfaces,
    scan_network,
    enrich_devices,
    export_json,
    export_csv,
)

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# ─── Estado global del escaneo ───────────────────────────────────────────────
_scan_state = {
    "status": "idle",       # idle | scanning | enriching | done | error
    "progress": 0,
    "total": 0,
    "message": "",
    "devices": [],
    "started_at": None,
    "finished_at": None,
    "network": "",
    "error": None,
}
_scan_lock = threading.Lock()


def _update_state(**kwargs):
    with _scan_lock:
        _scan_state.update(kwargs)


def _do_scan(network):
    """Función que corre en un hilo separado para el escaneo completo."""
    try:
        _update_state(
            status="scanning",
            progress=0,
            total=0,
            message=f"Enviando paquetes ARP a {network}...",
            devices=[],
            error=None,
            started_at=time.time(),
            network=network,
        )

        # Fase 1: ARP scan
        raw_devices = scan_network(network)
        count = len(raw_devices)

        if count == 0:
            _update_state(
                status="done",
                message="No se encontraron dispositivos. Verificar permisos de administrador.",
                devices=[],
                finished_at=time.time(),
            )
            return

        _update_state(
            status="enriching",
            total=count,
            progress=0,
            message=f"Encontrados {count} dispositivos. Obteniendo detalles...",
        )

        # Fase 2: Enriquecimiento paralelo
        def on_progress(current, total):
            _update_state(progress=current, total=total,
                          message=f"Procesando dispositivo {current} de {total}...")

        enriched = enrich_devices(raw_devices, max_workers=20, progress_callback=on_progress)

        # Guardar resultados
        export_json(enriched)

        _update_state(
            status="done",
            devices=enriched,
            progress=count,
            total=count,
            message=f"Escaneo completo. {count} dispositivos encontrados.",
            finished_at=time.time(),
        )

    except Exception as e:
        _update_state(
            status="error",
            error=str(e),
            message=f"Error durante el escaneo: {e}",
            finished_at=time.time(),
        )


# ─── Rutas API ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Sirve el frontend principal."""
    return send_from_directory("static", "index.html")


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """Retorna las interfaces de red disponibles y la subred detectada."""
    interfaces = get_local_interfaces()
    auto_network = get_local_network()
    return jsonify({
        "interfaces": interfaces,
        "auto_network": auto_network,
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Inicia un nuevo escaneo.
    Body JSON: { "network": "192.168.1.0/24" }  (opcional, auto-detecta si no se envía)
    """
    with _scan_lock:
        if _scan_state["status"] in ("scanning", "enriching"):
            return jsonify({"error": "Ya hay un escaneo en curso."}), 409

    data = request.get_json(silent=True) or {}
    network = data.get("network") or get_local_network()

    if not network:
        return jsonify({"error": "No se pudo detectar la red. Especifícala manualmente."}), 400

    thread = threading.Thread(target=_do_scan, args=(network,), daemon=True)
    thread.start()

    return jsonify({"message": f"Escaneo iniciado en {network}", "network": network})


@app.route("/api/status", methods=["GET"])
def api_status():
    """Retorna el estado actual del escaneo."""
    with _scan_lock:
        state = dict(_scan_state)
    # No incluir todos los devices en el status (pueden ser muchos)
    state_summary = {k: v for k, v in state.items() if k != "devices"}
    state_summary["device_count"] = len(state.get("devices", []))
    return jsonify(state_summary)


@app.route("/api/results", methods=["GET"])
def api_results():
    """Retorna los resultados completos del último escaneo."""
    with _scan_lock:
        devices = list(_scan_state["devices"])
        status = _scan_state["status"]
        network = _scan_state["network"]
    return jsonify({
        "status": status,
        "network": network,
        "devices": devices,
        "count": len(devices),
    })


@app.route("/api/stream", methods=["GET"])
def api_stream():
    """
    Server-Sent Events (SSE) para actualizaciones en tiempo real del progreso.
    El frontend puede hacer EventSource('/api/stream') para escuchar.
    """
    def event_stream():
        last_status = None
        last_progress = -1
        while True:
            with _scan_lock:
                current_status = _scan_state["status"]
                current_progress = _scan_state["progress"]
                current_total = _scan_state["total"]
                current_message = _scan_state["message"]
                current_count = len(_scan_state["devices"])

            if current_status != last_status or current_progress != last_progress:
                payload = json.dumps({
                    "status": current_status,
                    "progress": current_progress,
                    "total": current_total,
                    "message": current_message,
                    "device_count": current_count,
                })
                yield f"data: {payload}\n\n"
                last_status = current_status
                last_progress = current_progress

            if current_status == "done" or current_status == "error":
                break

            time.sleep(0.5)

    return Response(event_stream(), content_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/export/json", methods=["GET"])
def api_export_json():
    """Exporta resultados como JSON descargable."""
    with _scan_lock:
        devices = list(_scan_state["devices"])
    filepath = export_json(devices)
    return send_from_directory("results", "devices.json", as_attachment=True)


@app.route("/api/export/csv", methods=["GET"])
def api_export_csv():
    """Exporta resultados como CSV descargable."""
    with _scan_lock:
        devices = list(_scan_state["devices"])
    filepath = export_csv(devices)
    return send_from_directory("results", "devices.csv", as_attachment=True)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Señaliza cancelación del escaneo (best-effort)."""
    with _scan_lock:
        if _scan_state["status"] in ("scanning", "enriching"):
            _scan_state["status"] = "idle"
            _scan_state["message"] = "Escaneo cancelado por el usuario."
    return jsonify({"message": "Señal de cancelación enviada."})


if __name__ == "__main__":
    print("\n[*] Escaner de Red iniciado en http://localhost:5050")
    print("   Abre tu navegador en: http://localhost:5050\n")
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
