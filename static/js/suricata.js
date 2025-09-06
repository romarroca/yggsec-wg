let auto = false, timer = null;

// Suricata status monitoring (read-only)
async function loadSuricataStatus(){
  try{
    const r = await fetch('/api/suricata/status', {
      cache:'no-store',
      credentials: 'same-origin'
    });
    const j = await r.json();
    
    const isOn = j.mode === 'ON';
    
    // Update status badges
    const statusBadge = document.getElementById('suri-status');
    statusBadge.textContent = isOn ? 'ON' : 'OFF';
    statusBadge.className = 'badge ' + (isOn ? 'bg-success' : 'bg-secondary');
    
    const modeBadge = document.getElementById('ips-mode');
    modeBadge.textContent = isOn ? 'ACTIVE' : 'INACTIVE';
    modeBadge.className = 'badge ' + (isOn ? 'bg-success' : 'bg-secondary');
    
  }catch(e){
    document.getElementById('suri-status').textContent = 'Error';
    document.getElementById('suri-status').className = 'badge bg-danger';
    document.getElementById('ips-mode').textContent = 'Error';
    document.getElementById('ips-mode').className = 'badge bg-danger';
  }
}

async function clearLogs(){
  if(!confirm('Clear all cached alerts? This cannot be undone.')) return;
  
  const btn = document.getElementById('clear-btn');
  const originalText = btn.textContent;
  
  btn.disabled = true;
  btn.textContent = 'Clearing...';
  
  try{
    const formData = new FormData();
    
    // Get CSRF token from hidden form
    const csrfToken = document.querySelector('#clear-form input[name="csrf_token"]').value;
    formData.append('csrf_token', csrfToken);
    
    const r = await fetch('/api/suricata/clear', {
      method: 'POST',
      body: formData,
      credentials: 'same-origin'
    });
    const j = await r.json();
    
    if(j.success){
      refreshEve(); // Refresh to show cleared state
    } else {
      alert('Failed to clear logs');
    }
  }catch(e){
    alert('Error clearing logs: ' + e.message);
  }finally{
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

function setAutoBtn(on){
  const b=document.getElementById('auto-btn');
  if(on){ b.textContent='Auto Refresh: On'; b.classList.remove('btn-outline-secondary'); b.classList.add('btn-success'); }
  else { b.textContent='Auto Refresh: Off'; b.classList.remove('btn-success'); b.classList.add('btn-outline-secondary'); }
}

async function refreshEve(){
  const n = document.getElementById('rows-select').value || 200;
  try{
    const r = await fetch(`/api/suricata/eve?n=${encodeURIComponent(n)}`, {cache:'no-store'});
    const j = await r.json();
    const rows = (j.alerts||[]).map(a=>`
      <tr>
        <td>${a.time||''}</td>
        <td>${a.sig||''}</td>
        <td>${a.cat||''}</td>
        <td class="text-end">${a.sev??''}</td>
        <td>${a.proto||''}</td>
        <td>${a.src||''}</td>
        <td>${a.dst||''}</td>
      </tr>`).join('');
    const tbody = document.getElementById('tbl-suri');
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    if (rows) {
      tbody.innerHTML = rows;
    } else {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'text-muted';
      td.textContent = 'No events.';
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }catch(e){
    console.error('Failed to refresh Suricata logs:', e);
  }
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
  loadSuricataStatus();
  refreshEve();
  
  // Bind event handlers
  document.getElementById('refresh-btn').addEventListener('click', refreshEve);
  document.getElementById('clear-btn').addEventListener('click', clearLogs);
  
  document.getElementById('auto-btn').addEventListener('click', () => {
    auto = !auto;
    setAutoBtn(auto);
    if(auto){
      refreshEve();
      timer = setInterval(refreshEve, 10000);
    } else {
      clearInterval(timer);
      timer = null;
    }
  });
  
  document.getElementById('rows-select').addEventListener('change', refreshEve);
});