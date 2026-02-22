/**
 * Zero-Day Prevention System — EDR Dashboard
 * Fetches alerts from /api/alerts every 5 s and updates the UI without a page reload.
 */

'use strict';

/* ─── Config ─────────────────────────────────────────────────── */
const REFRESH_INTERVAL_MS = 5000;
const CPU_HIGH_THRESHOLD  = 85;
const MEM_HIGH_THRESHOLD  = 800;

/* ─── DOM refs ───────────────────────────────────────────────── */
const alertsBody      = document.getElementById('alertsBody');
const alertsBadge     = document.getElementById('alertsBadge');
const statTotal       = document.getElementById('statTotal');
const statHigh        = document.getElementById('statHigh');
const statLast        = document.getElementById('statLast');
const lastRefreshTime = document.getElementById('lastRefreshTime');
const rowCountEl      = document.getElementById('rowCount');
const searchBox       = document.getElementById('searchBox');
const sortBtn         = document.getElementById('sortBtn');

/* ─── State ──────────────────────────────────────────────────── */
let allAlerts  = [];
let sortAsc    = false;   // start: newest first

/* ══════════════════════════════════════════════════════════════
   THREAT LEVEL LOGIC
══════════════════════════════════════════════════════════════ */
function getThreatLevel(alert) {
  const cpu    = parseFloat(alert.cpu)    || 0;
  const memory = parseFloat(alert.memory) || 0;
  const path   = (alert.path || '').toLowerCase();

  const isSuspiciousPath = ['/tmp/', '/var/tmp/', '/private/tmp/', '/downloads/']
      .some(p => path.includes(p));

  if (cpu > CPU_HIGH_THRESHOLD || memory > MEM_HIGH_THRESHOLD || isSuspiciousPath) {
    return 'high';
  }
  if (cpu > 50 || memory > 400) {
    return 'medium';
  }
  return 'low';
}

/* ══════════════════════════════════════════════════════════════
   RENDERING
══════════════════════════════════════════════════════════════ */
function formatTimestamp(ts) {
  if (!ts || ts === 'N/A') return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return ts; }
}

function buildRow(alert) {
  const level     = getThreatLevel(alert);
  const cpu       = parseFloat(alert.cpu)    || 0;
  const memory    = parseFloat(alert.memory) || 0;
  const cpuClass  = cpu    > CPU_HIGH_THRESHOLD ? 'high' : '';
  const memClass  = memory > MEM_HIGH_THRESHOLD ? 'high' : '';

  const badgeMap = {
    high:   '<span class="badge badge-high">High</span>',
    medium: '<span class="badge badge-medium">Medium</span>',
    low:    '<span class="badge badge-low">Low</span>',
  };

  const tr = document.createElement('tr');
  tr.classList.add(`row-${level}`);
  tr.dataset.search = [
    alert.timestamp, alert.name, alert.pid, alert.cpu, alert.memory, alert.path
  ].map(v => String(v || '').toLowerCase()).join(' ');

  tr.innerHTML = `
    <td class="col-timestamp">${formatTimestamp(alert.timestamp)}</td>
    <td class="col-name">${escHtml(alert.name || '—')}</td>
    <td class="col-pid">${escHtml(String(alert.pid || '—'))}</td>
    <td class="col-cpu ${cpuClass}">${cpu.toFixed(1)}&thinsp;%</td>
    <td class="col-mem ${memClass}">${memory.toFixed(1)}&thinsp;MB</td>
    <td class="col-path" title="${escHtml(alert.path || '')}">${escHtml(alert.path || '—')}</td>
    <td>${badgeMap[level]}</td>
  `;
  return tr;
}

function renderTable(alerts) {
  alertsBody.innerHTML = '';

  if (!alerts || alerts.length === 0) {
    alertsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="7">
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <polyline points="9 12 11 14 15 10"/>
            </svg>
            <p>No alerts detected. System is clean.</p>
          </div>
        </td>
      </tr>`;
    return;
  }

  const fragment = document.createDocumentFragment();
  alerts.forEach(a => fragment.appendChild(buildRow(a)));
  alertsBody.appendChild(fragment);
}

function updateStats(alerts) {
  const total = alerts.length;
  const highCount = alerts.filter(a => getThreatLevel(a) === 'high').length;

  statTotal.textContent = total;
  alertsBadge.textContent = total;

  statHigh.textContent = highCount;

  if (total > 0) {
    const last = alerts[alerts.length - 1];
    statLast.textContent = formatTimestamp(last.timestamp);
  } else {
    statLast.textContent = 'None';
  }

  const now = new Date();
  lastRefreshTime.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
}

function updateRowCount() {
  const visible = alertsBody.querySelectorAll('tr:not(.empty-row):not(.row-hidden)').length;
  rowCountEl.textContent = `${visible} alert${visible !== 1 ? 's' : ''} shown`;
}

/* ══════════════════════════════════════════════════════════════
   SEARCH FILTER
══════════════════════════════════════════════════════════════ */
function applySearch(query) {
  const q = query.trim().toLowerCase();
  const rows = alertsBody.querySelectorAll('tr:not(.empty-row)');
  rows.forEach(row => {
    const match = !q || (row.dataset.search || '').includes(q);
    row.classList.toggle('row-hidden', !match);
  });
  updateRowCount();
}

searchBox.addEventListener('input', () => applySearch(searchBox.value));

/* ══════════════════════════════════════════════════════════════
   SORT
══════════════════════════════════════════════════════════════ */
sortBtn.addEventListener('click', () => {
  sortAsc = !sortAsc;
  const sorted = [...allAlerts].sort((a, b) => {
    const ta = new Date(a.timestamp || 0).getTime();
    const tb = new Date(b.timestamp || 0).getTime();
    return sortAsc ? ta - tb : tb - ta;
  });
  renderTable(sorted);
  applySearch(searchBox.value);
  updateRowCount();
  sortBtn.textContent = sortAsc ? 'Sort ↑' : 'Sort ↓';
});

/* ══════════════════════════════════════════════════════════════
   DATA FETCHING
══════════════════════════════════════════════════════════════ */
async function fetchAlerts() {
  try {
    const res = await fetch('/api/alerts');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Sort newest first by default
    allAlerts = [...data].sort((a, b) => {
      return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
    });

    renderTable(allAlerts);
    updateStats(allAlerts);
    applySearch(searchBox.value);
    updateRowCount();
  } catch (err) {
    console.error('[dashboard] Failed to fetch alerts:', err);
  }
}

/* ══════════════════════════════════════════════════════════════
   UTILITY
══════════════════════════════════════════════════════════════ */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ══════════════════════════════════════════════════════════════
   INIT
══════════════════════════════════════════════════════════════ */
fetchAlerts();
setInterval(fetchAlerts, REFRESH_INTERVAL_MS);
