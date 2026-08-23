# 🌐 Escáner de Red Local — Guía de Uso

## ¿Qué es esto?

Un escáner de red local premium que descubre **todos los dispositivos** conectados a tu red:
- IPs, MACs, fabricantes
- Hostname, puertos abiertos
- Identificación automática de routers **Ruijie**, IoT, PCs, cámaras, etc.
- Dashboard web tipo **Colasoft MAC Scanner Pro**

---

## Instalación rápida

### Requisitos
- Python 3.8 o superior
- **Npcap** (para Windows) → [descargar aquí](https://npcap.com/#download)
- Correr como **Administrador** (necesario para escaneo ARP)

### Paso 1 — Instalar Npcap (solo Windows, una vez)
Descarga e instala desde: https://npcap.com/#download

### Paso 2 — Instalar dependencias Python
```bash
pip install flask flask-cors scapy netifaces requests rich
```

### Paso 3 — Correr el escáner
**Clic derecho → "Ejecutar como administrador"** en PowerShell, luego:
```bash
python run.py
```

El navegador se abrirá automáticamente en `http://localhost:5050`

---

## 💻 Guía de Uso paso a paso (Nivel Usuario)

### 1. ¿Cómo inicio el sistema?
1. Abre el menú inicio de Windows, escribe **PowerShell**.
2. Dale clic derecho y selecciona **"Ejecutar como administrador"**.
3. Navega a la carpeta del proyecto escribiendo:
   ```bash
   cd "C:\Users\richa\Music\Escaner Red"
   ```
4. Inicia el sistema ejecutando:
   ```bash
   python run.py
   ```
*Nota: Si te pregunta si quieres permisos de administrador, dile que sí.*

### 2. ¿Cómo veo el frontend (la interfaz)?
Si usaste `python run.py`, **el navegador se abrirá automáticamente** mostrando el dashboard.
Si no se abre, o lo cerraste por error, simplemente abre tu navegador (Chrome, Edge, etc.) y entra a esta dirección:
👉 **http://localhost:5050**

### 3. ¿Cómo usar el escáner?
1. En el dashboard, la red se **detecta automáticamente** (ej: `192.168.1.0/24`).
2. Presioná el botón **"Escanear Red"**.
3. Esperá a que la barra de progreso termine.
4. Los dispositivos aparecerán en la tabla. **Tu router Ruijie** se destacará en verde ⭐.
*Si querés escanear el segmento 10, borrá el texto automático y escribí `192.168.10.0/24` antes de darle a escanear.*

### 4. ¿Cómo paro o apago el servidor?
Para apagar el servidor y dejar de usar el escáner:
1. Ve a la ventana azul de **PowerShell** donde escribiste el comando.
2. Presiona las teclas **`Ctrl + C`** al mismo tiempo.
3. Verás un mensaje que dice `[✓] Servidor detenido. ¡Hasta luego!`. Ya puedes cerrar la ventana.

### 4.b. ¿Cómo REINICIAR el servidor?
Si hiciste cambios o la página se quedó trabada y necesitas reiniciar el servidor:
1. Ve a la ventana de **PowerShell** y presiona **`Ctrl + C`** para pararlo.
2. Una vez que se detenga, simplemente vuelve a escribir el comando para iniciarlo:
   ```bash
   python run.py
   ```
3. Refresca la página en tu navegador (`F5`).

### 5. ¿Qué pasa si el puerto ya está en uso? (Matar procesos huérfanos)
Si al intentar iniciar el sistema te da un error diciendo que el puerto `5050` está en uso (esto pasa si cerraste la ventana sin presionar `Ctrl + C`), puedes "matar" el proceso anterior para no pisarlo:

**Desde PowerShell (como administrador):**
```bash
Stop-Process -Id (Get-NetTCPConnection -LocalPort 5050).OwningProcess -Force
```
Y luego vuelve a iniciar con `python run.py`.

---

## Estructura del proyecto

```
Escaner Red/
├── main.py          ← Scanner original (conservado)
├── scanner.py       ← Scanner mejorado (nuevo)
├── api.py           ← Servidor Flask REST + SSE
├── run.py           ← Lanzador unificado
├── requirements.txt
├── static/
│   ├── index.html   ← Dashboard web premium
│   ├── style.css    ← Diseño dark glassmorphism
│   └── app.js       ← Lógica frontend
└── results/
    ├── devices.json ← Último escaneo (JSON)
    └── devices.csv  ← Último escaneo (CSV)
```

---

## Endpoints API disponibles

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/` | Dashboard web |
| GET | `/api/interfaces` | Interfaces de red detectadas |
| POST | `/api/scan` | Iniciar escaneo |
| GET | `/api/status` | Estado del escaneo |
| GET | `/api/results` | Resultados completos (JSON) |
| GET | `/api/stream` | SSE en tiempo real |
| GET | `/api/export/json` | Descargar resultados JSON |
| GET | `/api/export/csv` | Descargar resultados CSV |
| POST | `/api/stop` | Detener escaneo |

---

## Solución de problemas

**"No devices found"** → Asegurate de correr como Administrador y que Npcap esté instalado.

**"Scapy import error"** → Instala Npcap desde https://npcap.com

**El router Ruijie no aparece** → Puede que esté en otra subred. Probá manualmente con `192.168.0.0/24` o `192.168.1.0/24`.

---

## Créditos y Licencia

**Diseñado por Richard Campos - PMO**

Este proyecto se distribuye bajo una **Licencia Abierta de Uso General**. Eres libre de usar, modificar y distribuir este software para cualquier propósito, comercial o no comercial, siempre y cuando se mantenga el reconocimiento al autor original.
