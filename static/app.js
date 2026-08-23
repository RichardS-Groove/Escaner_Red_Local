/* ═══════════════════════════════════════════════════════════
   Escáner de Red — Frontend App Logic
   ══════════════════════════════════════════════════════════ */

'use strict';

// ─── Estado de la app ────────────────────────────────────
let allDevices = [];
let filteredDevices = [];
let currentTypeFilter = 'all';
let currentSort = { key: 'ip', dir: 1 };
let eventSource = null;
let pollInterval = null;

// ─── Inicialización ──────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  loadInterfaces();
  loadTheme();
});

// ─── Tema claro/oscuro ───────────────────────────────────
function loadTheme() {
  const saved = localStorage.getItem('scanner-theme') || 'light';
  applyTheme(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  localStorage.setItem('scanner-theme', next);
}

function applyTheme(theme) {
  if (theme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.getElementById('themeIcon').textContent = '🌙';
  } else {
    document.documentElement.removeAttribute('data-theme');
    document.getElementById('themeIcon').textContent = '☀️';
  }
}

async function loadInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    if (data.auto_network) {
      document.getElementById('networkInput').placeholder =
        `Auto-detectado: ${data.auto_network}`;
      document.getElementById('netLabel').textContent = data.auto_network;
    }
    if (data.interfaces && data.interfaces.length > 0) {
      const iface = data.interfaces[0];
      document.getElementById('netLabel').textContent = `${iface.network} · ${iface.ip}`;
    }
  } catch (e) {
    document.getElementById('netLabel').textContent = 'Sin conexión al servidor';
  }
}

// ─── Iniciar escaneo ─────────────────────────────────────
async function startScan(forcedNetwork = null) {
  const networkInput = forcedNetwork || document.getElementById('networkInput').value.trim();

  try {
    const body = networkInput ? { network: networkInput } : {};
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Error: ${err.error}`);
      return;
    }

    const data = await res.json();
    console.log('Scan started:', data);
  } catch (e) {
    alert('No se pudo conectar al servidor. ¿Está corriendo api.py?');
    return;
  }

  // UI: modo escaneo
  setScanning(true);
  resetResults();
  startStreamListener();
}

// ─── Detener escaneo ─────────────────────────────────────
async function stopScan() {
  try {
    await fetch('/api/stop', { method: 'POST' });
  } catch (e) {}
  setScanning(false);
  stopStreamListener();
}

// ─── SSE Listener ────────────────────────────────────────
function startStreamListener() {
  stopStreamListener();

  eventSource = new EventSource('/api/stream');

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    updateProgress(data);

    if (data.status === 'done') {
      stopStreamListener();
      setScanning(false);
      fetchResults();
    } else if (data.status === 'error') {
      stopStreamListener();
      setScanning(false);
      showProgressMsg(`❌ Error: ${data.message}`);
    }
  };

  eventSource.onerror = () => {
    // SSE cerrado normalmente al terminar
    stopStreamListener();
    // Intentar obtener resultados igual
    setTimeout(fetchResults, 800);
  };
}

function stopStreamListener() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

// ─── Actualizar progreso ──────────────────────────────────
function updateProgress(data) {
  const { status, progress, total, message } = data;

  showProgressMsg(message || '...');

  if (total > 0) {
    const pct = Math.round((progress / total) * 100);
    setProgressBar(pct);
  } else if (status === 'scanning') {
    // Animación indeterminada
    animateIndeterminate();
  }
}

let indeterminateInterval = null;
let indeterminateVal = 0;

function animateIndeterminate() {
  if (indeterminateInterval) return;
  indeterminateInterval = setInterval(() => {
    indeterminateVal = (indeterminateVal + 2) % 100;
    setProgressBar(indeterminateVal);
  }, 60);
}

function stopIndeterminate() {
  if (indeterminateInterval) {
    clearInterval(indeterminateInterval);
    indeterminateInterval = null;
  }
}

function setProgressBar(pct) {
  document.getElementById('progressFill').style.width = `${pct}%`;
}

function showProgressMsg(msg) {
  document.getElementById('progressMsg').textContent = msg;
}

// ─── Obtener resultados ───────────────────────────────────
async function fetchResults() {
  try {
    const res = await fetch('/api/results');
    const data = await res.json();
    allDevices = data.devices || [];
    renderAll();
  } catch (e) {
    console.error('Error fetching results:', e);
  }
}

// ─── UI helpers ──────────────────────────────────────────
function setScanning(active) {
  const btnScan = document.getElementById('btnScan');
  const btnStop = document.getElementById('btnStop');
  const progressWrapper = document.getElementById('progressWrapper');
  const btnScanEl = document.getElementById('btnScan');

  if (active) {
    btnScan.classList.add('hidden');
    btnStop.classList.remove('hidden');
    progressWrapper.style.display = 'block';
    btnScanEl.classList.add('scanning-active');
  } else {
    btnScan.classList.remove('hidden');
    btnStop.classList.add('hidden');
    btnScanEl.classList.remove('scanning-active');
    stopIndeterminate();
    setProgressBar(100);
  }
}

function resetResults() {
  allDevices = [];
  filteredDevices = [];
  document.getElementById('deviceBody').innerHTML = '';
  document.getElementById('statsRow').style.display = 'none';
  document.getElementById('filterBar').style.display = 'none';
  document.getElementById('resultsSection').style.display = 'none';
  document.getElementById('emptyState').style.display = 'none';
  document.getElementById('btnExportJson').classList.add('hidden');
  document.getElementById('btnExportCsv').classList.add('hidden');
}

// ─── Render principal ─────────────────────────────────────
function renderAll() {
  applyFilter();
  renderStats();
  showResultsUI();
}

function showResultsUI() {
  document.getElementById('statsRow').style.display = 'grid';
  document.getElementById('filterBar').style.display = 'flex';
  document.getElementById('resultsSection').style.display = 'block';
  document.getElementById('emptyState').style.display = 'none';
  document.getElementById('btnExportJson').classList.remove('hidden');
  document.getElementById('btnExportCsv').classList.remove('hidden');
}

// ─── Estadísticas ────────────────────────────────────────
function renderStats() {
  const total = allDevices.length;
  const routers = allDevices.filter(d => d.device_type === 'router').length;
  const computers = allDevices.filter(d => d.device_type === 'computer' || d.device_type === 'server').length;
  const iot = allDevices.filter(d => d.device_type === 'iot' || d.device_type === 'camera' || d.device_type === 'printer').length;

  // Detectar red desde el primer dispositivo
  let netLabel = '—';
  if (allDevices.length > 0) {
    const firstIp = allDevices[0].ip || '';
    const parts = firstIp.split('.');
    if (parts.length === 4) netLabel = `${parts[0]}.${parts[1]}.${parts[2]}.x`;
  }

  document.getElementById('statTotal').textContent = total;
  document.getElementById('statRouters').textContent = routers;
  document.getElementById('statComputers').textContent = computers;
  document.getElementById('statIot').textContent = iot;
  document.getElementById('statNetwork').textContent = netLabel;
}

// ─── Filtros ─────────────────────────────────────────────
function setTypeFilter(type, btn) {
  currentTypeFilter = type;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('chip-active'));
  btn.classList.add('chip-active');
  applyFilter();
}

function applyFilter() {
  const query = document.getElementById('filterInput').value.toLowerCase().trim();

  filteredDevices = allDevices.filter(d => {
    // Type filter
    if (currentTypeFilter !== 'all' && d.device_type !== currentTypeFilter) return false;
    // Text search
    if (query) {
      const searchable = [
        d.ip, d.mac, d.vendor, d.hostname, d.device_type,
        ...(d.open_ports || []).map(p => `${p.port} ${p.name}`)
      ].join(' ').toLowerCase();
      if (!searchable.includes(query)) return false;
    }
    return true;
  });

  sortDevices();
  renderTable();
}

// ─── Ordenamiento ─────────────────────────────────────────
function sortBy(key) {
  if (currentSort.key === key) {
    currentSort.dir *= -1;
  } else {
    currentSort.key = key;
    currentSort.dir = 1;
  }
  sortDevices();
  renderTable();
}

function sortDevices() {
  const { key, dir } = currentSort;
  filteredDevices.sort((a, b) => {
    if (key === 'ip') {
      // Ordenar IPs numéricamente
      const aNum = (a.ip || '').split('.').map(Number);
      const bNum = (b.ip || '').split('.').map(Number);
      for (let i = 0; i < 4; i++) {
        if (aNum[i] !== bNum[i]) return dir * (aNum[i] - bNum[i]);
      }
      return 0;
    }
    const aVal = (a[key] || '').toLowerCase();
    const bVal = (b[key] || '').toLowerCase();
    return dir * aVal.localeCompare(bVal);
  });
}

// ─── Render tabla ─────────────────────────────────────────
function renderTable() {
  const tbody = document.getElementById('deviceBody');
  const noResults = document.getElementById('noResults');

  if (filteredDevices.length === 0) {
    tbody.innerHTML = '';
    noResults.classList.remove('hidden');
    return;
  }

  noResults.classList.add('hidden');

  tbody.innerHTML = filteredDevices.map((d, i) => {
    const icon = deviceIcon(d.device_type);
    const typeBadge = deviceBadge(d.device_type);
    const isRouter = d.device_type === 'router';
    const isRuijie = (d.vendor || '').toLowerCase().includes('ruijie');

    const vendorHtml = isRuijie
      ? `<span class="vendor-ruijie">${escapeHtml(d.vendor || '')} <small style="opacity:.6;font-size:.7em">RUIJIE</small></span>`
      : escapeHtml(d.vendor || 'Desconocido');

    const portsHtml = (d.open_ports || []).length > 0
      ? `<div class="td-ports">${(d.open_ports || []).map(p =>
          `<span class="port-badge" title="${p.name}">${p.port}</span>`
        ).join('')}</div>`
      : `<span style="color:var(--text-muted);font-size:.78rem">Ninguno</span>`;

    const rowClass = isRouter ? 'row-router' : '';

    return `<tr class="${rowClass}" onclick="showDeviceDetail(${i})" style="animation-delay:${i * 0.03}s">
      <td class="td-type-icon">${icon}</td>
      <td class="td-ip">
        <div class="ip-actions">
          <a href="http://${escapeHtml(d.ip)}" target="_blank" class="ip-link" onclick="event.stopPropagation()" title="Abrir en navegador">${escapeHtml(d.ip || '')}</a>
          <button class="ip-copy-btn" onclick="event.stopPropagation(); copyIp('${escapeHtml(d.ip)}')" title="Copiar IP">📋</button>
        </div>
      </td>
      <td class="td-mac">${escapeHtml(d.mac || '')}</td>
      <td class="td-vendor">${vendorHtml}</td>
      <td class="td-hostname">${escapeHtml(d.hostname || '—')}</td>
      <td>${portsHtml}</td>
      <td>${typeBadge}</td>
    </tr>`;
  }).join('');
}

// ─── Modal de detalle ─────────────────────────────────────
function showDeviceDetail(idx) {
  const d = filteredDevices[idx];
  if (!d) return;

  const icon = deviceIcon(d.device_type);
  const badge = deviceBadge(d.device_type);
  const isRuijie = (d.vendor || '').toLowerCase().includes('ruijie');
  const ruijieNote = isRuijie
    ? `<div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:8px;padding:12px 16px;margin-bottom:16px;color:#10b981;font-size:.85rem;">
        ⭐ <strong>¡Router Ruijie detectado!</strong> Esta es posiblemente la IP de tu router AX3200.
      </div>` : '';

  const portsHtml = (d.open_ports || []).length > 0
    ? `<div class="modal-ports">${(d.open_ports || []).map(p =>
        `<span class="port-badge">${p.port}/${p.name}</span>`
      ).join('')}</div>`
    : 'Ninguno';

  const content = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
      <span style="font-size:2rem">${icon}</span>
      <h2 class="modal-title" style="margin:0">${escapeHtml(d.ip || '')}</h2>
      ${badge}
    </div>
    ${ruijieNote}
    <div class="modal-detail-row">
      <span class="modal-detail-key">IP Address</span>
      <span class="modal-detail-val" style="color:var(--accent-cyan)">${escapeHtml(d.ip || '')}</span>
    </div>
    <div class="modal-detail-row">
      <span class="modal-detail-key">MAC Address</span>
      <span class="modal-detail-val">${escapeHtml(d.mac || '')}</span>
    </div>
    <div class="modal-detail-row">
      <span class="modal-detail-key">Fabricante</span>
      <span class="modal-detail-val">${escapeHtml(d.vendor || 'Desconocido')}</span>
    </div>
    <div class="modal-detail-row">
      <span class="modal-detail-key">Hostname</span>
      <span class="modal-detail-val">${escapeHtml(d.hostname || '—')}</span>
    </div>
    <div class="modal-detail-row">
      <span class="modal-detail-key">Tipo</span>
      <span class="modal-detail-val">${d.device_type || 'unknown'}</span>
    </div>
    <div class="modal-detail-row">
      <span class="modal-detail-key">Puertos</span>
      <div class="modal-detail-val">${portsHtml}</div>
    </div>
    ${d.is_router ? `
    <div style="margin-top:20px;padding:16px;background:rgba(0,212,255,0.06);border-radius:8px;border:1px solid rgba(0,212,255,0.15)">
      <p style="font-size:.8rem;color:var(--text-secondary);margin-bottom:8px">💡 <strong>Acceder al panel del router:</strong></p>
      <a href="http://${d.ip}" target="_blank" style="color:var(--accent-cyan);font-family:var(--font-mono);font-size:.85rem">
        http://${escapeHtml(d.ip)} →
      </a>
    </div>` : ''}
  `;

  document.getElementById('modalContent').innerHTML = content;
  document.getElementById('modalOverlay').classList.remove('hidden');
}

function closeModal(event) {
  if (!event || event.target === document.getElementById('modalOverlay') || event.target === document.querySelector('.modal-close')) {
    document.getElementById('modalOverlay').classList.add('hidden');
  }
}

// ─── Export ───────────────────────────────────────────────
function exportData(format) {
  window.open(`/api/export/${format}`, '_blank');
}

// ─── Utilidades ───────────────────────────────────────────
function deviceIcon(type) {
  const icons = {
    router:   '🌐',
    computer: '💻',
    server:   '🖥',
    iot:      '📡',
    camera:   '📷',
    printer:  '🖨',
    unknown:  '❓',
  };
  return icons[type] || '❓';
}

function deviceBadge(type) {
  const labels = {
    router:   'Router',
    computer: 'PC',
    server:   'Server',
    iot:      'IoT',
    camera:   'Cámara',
    printer:  'Impresora',
    unknown:  'Desconocido',
  };
  const cls = `type-badge type-${type || 'unknown'}`;
  return `<span class="${cls}">${deviceIcon(type)} ${labels[type] || 'Desconocido'}</span>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function copyIp(ip) {
  navigator.clipboard.writeText(ip).then(() => {
    // Feedback visual temporal
    const btn = event.target;
    const original = btn.textContent;
    btn.textContent = '✅';
    setTimeout(() => { btn.textContent = original; }, 1200);
  }).catch(() => {
    // Fallback para navegadores antiguos
    const input = document.createElement('input');
    input.value = ip;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
  });
}
