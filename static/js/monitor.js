let autoRefresh = false;
let autoTimer = null;

function setAutoButton(on) {
  const btn = document.getElementById('auto-btn');
  if (!btn) return;
  if (on) {
    btn.textContent = 'Auto Refresh: On';
    btn.classList.remove('btn-outline-secondary');
    btn.classList.add('btn-success');
  } else {
    btn.textContent = 'Auto Refresh: Off';
    btn.classList.remove('btn-success');
    btn.classList.add('btn-outline-secondary');
  }
}

function td(text, cls) {
  const el = document.createElement('td');
  if (cls) el.className = cls;
  el.textContent = text;
  return el;
}

function renderRows(tbodyId, rows, cols) {
  const tbody = document.getElementById(tbodyId);
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
  if (!rows || rows.length === 0) {
    const tr = document.createElement('tr');
    const tdEmpty = document.createElement('td');
    tdEmpty.colSpan = cols;
    tdEmpty.className = 'text-muted';
    tdEmpty.textContent = 'No data';
    tr.appendChild(tdEmpty);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach(r => tbody.appendChild(r));
}

async function refreshMonitor() {
  try {
    const res = await fetch('/api/monitor', { cache: 'no-store' });
    const data = await res.json();

    const tsEl = document.getElementById('snapshot-time');
    if (tsEl) tsEl.textContent = data.timestamp || '';

    const srcRows = (data.ips_seen?.sources || []).map(s => {
      const tr = document.createElement('tr');
      tr.appendChild(td(s.ip || '—'));
      tr.appendChild(td(String(s.flows ?? 0), 'text-end'));
      return tr;
    });
    renderRows('tbl-top-sources', srcRows, 2);

    const dstRows = (data.ips_seen?.destinations || []).map(d => {
      const tr = document.createElement('tr');
      tr.appendChild(td(d.ip || '—'));
      tr.appendChild(td(String(d.flows ?? 0), 'text-end'));
      return tr;
    });
    renderRows('tbl-top-dests', dstRows, 2);

    const portRows = (data.ips_seen?.top_ports_by_flows || []).map(p => {
      const tr = document.createElement('tr');
      tr.appendChild(td(p.port ?? '—'));
      tr.appendChild(td(p.service || 'Unknown'));
      tr.appendChild(td(String(p.flows ?? 0), 'text-end'));
      return tr;
    });
    renderRows('tbl-ports', portRows, 3);

    const ifRows = (data.interfaces || []).map(i => {
      const tr = document.createElement('tr');
      tr.appendChild(td(i.iface || '—'));
      tr.appendChild(td(String(i.rx_bytes ?? 0), 'text-end'));
      tr.appendChild(td(String(i.rx_pkts ?? 0), 'text-end'));
      tr.appendChild(td(String(i.tx_bytes ?? 0), 'text-end'));
      tr.appendChild(td(String(i.tx_pkts ?? 0), 'text-end'));
      return tr;
    });
    renderRows('tbl-ifaces', ifRows, 5);

  } catch (err) {
    console.error('Refresh failed', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('refresh-btn').addEventListener('click', refreshMonitor);
  document.getElementById('auto-btn').addEventListener('click', () => {
    autoRefresh = !autoRefresh;
    setAutoButton(autoRefresh);
    if (autoRefresh) {
      refreshMonitor();
      autoTimer = setInterval(refreshMonitor, 5000);
    } else {
      clearInterval(autoTimer);
      autoTimer = null;
    }
  });
  
  // Initial refresh on page load
  refreshMonitor();
});