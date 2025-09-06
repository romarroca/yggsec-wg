// Firewall page functionality
function toggleIndexInput(v) {
  const el = document.getElementById('indexInput'); 
  if (el) el.style.display = (v === 'index') ? '' : 'none';
}

document.addEventListener('DOMContentLoaded', () => {
  // Add/Edit Rule Modal
  document.getElementById('addRuleModal').addEventListener('show.bs.modal', (e) => {
    const t = e.relatedTarget, m = e.target;
    const title = m.querySelector('.modal-title');
    const formAct = m.querySelector('#formAction');
    const handle = m.querySelector('#ruleHandle');
    const idxHid = m.querySelector('#ruleIndexHidden');
    const idxVis = m.querySelector('#ruleIndexVisible');
    const name = m.querySelector('#ruleName');
    const src = m.querySelector('#srcIp');
    const dst = m.querySelector('#dstIp');
    const port = m.querySelector('#portInput');
    const protoSel = m.querySelector('#protoSelect');
    const actSel = m.querySelector('#actionType');
    const posSel = m.querySelector('#positionSelect');

    const isEdit = !!(t && t.dataset && t.dataset.handle);

    if (isEdit) {
      title.textContent = 'Edit Rule';
      formAct.value = 'edit_rule';
      handle.value = t.dataset.handle || '';
      idxHid.value = t.dataset.line || '';
      idxVis.value = t.dataset.line || '';
      posSel.value = 'index'; 
      toggleIndexInput('index');

      name.value = t.dataset.name || '';
      src.value = t.dataset.src || '';
      dst.value = t.dataset.dst || '';
      port.value = t.dataset.dport || '';
      let p = (t.dataset.proto || '').toLowerCase(); 
      if (!p || p === 'any') p = 'any';
      if (['tcp', 'udp', 'icmp', 'tcpudp', 'any'].indexOf(p) === -1) p = 'any';
      protoSel.value = p;
      actSel.value = (t.dataset.action || 'TRUST').toUpperCase();
    } else {
      title.textContent = 'Add Rule';
      formAct.value = 'add_rule';
      handle.value = ''; 
      idxHid.value = ''; 
      idxVis.value = '';
      name.value = ''; 
      src.value = ''; 
      dst.value = ''; 
      port.value = '';
      protoSel.value = 'tcp'; 
      actSel.value = 'TRUST';
      posSel.value = 'append'; 
      toggleIndexInput('append');
    }
  });

  // Index input sync
  document.getElementById('ruleIndexVisible').addEventListener('input', () => {
    document.getElementById('ruleIndexHidden').value = document.getElementById('ruleIndexVisible').value;
  });

  // Reset confirmation functionality
  const resetBtn = document.getElementById('btnReset');
  const confirmBtn = document.getElementById('confirmResetBtn');
  const modalEl = document.getElementById('confirmResetModal');
  const modal = new bootstrap.Modal(modalEl);
  const form = document.getElementById('resetForm');

  resetBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    modal.show();
  });

  confirmBtn?.addEventListener('click', () => {
    modal.hide();
    form?.submit();
  });
});