// QR Code functionality for YggSec
document.addEventListener('DOMContentLoaded', () => {
  const qrModalEl = document.getElementById('qrModal');
  const qrModal   = new bootstrap.Modal(qrModalEl);
  const qrTitle   = document.getElementById('qrTitle');
  const qrCanvas  = document.getElementById('qrCanvas');
  const qrBox     = document.getElementById('qrBox');
  const qrError   = document.getElementById('qrError');

  function setError(msg, name) {
    qrCanvas.style.display = 'none';
    qrBox.style.display = 'none';
    while (qrBox.firstChild) qrBox.removeChild(qrBox.firstChild);
    qrError.style.display = 'block';
    qrError.textContent = msg;
    qrTitle.textContent = name || '';
    qrModal.show();
  }

  async function showQr(name) {
    try {
      if (!window.QRCode) return setError('QR library not loaded (js/qrcode.min.js missing).', name);

      const res = await fetch(`/api/spoke-config/${encodeURIComponent(name)}`, {
        cache: 'no-store',
        credentials: 'same-origin'
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const text = (data.config || "").replace(/\r\n/g, "\n").trim() + "\n";

      // reset
      qrError.style.display = 'none';
      qrCanvas.style.display = 'none';
      qrBox.style.display = 'none';
      while (qrBox.firstChild) qrBox.removeChild(qrBox.firstChild);

      // pure black on white + internal quiet zone
      const colorDark  = '#000000';
      const colorLight = '#ffffff';

      // Use the QRCode constructor approach
      if (typeof QRCode === 'function') {
        qrBox.style.display = 'block';
        new QRCode(qrBox, {
          text, width: 320, height: 320,
          colorDark, colorLight,
          correctLevel: QRCode.CorrectLevel ? QRCode.CorrectLevel.M : undefined
        });
      } else {
        return setError('QRCode constructor not available.', name);
      }

      qrTitle.textContent = name;
      qrModal.show();
    } catch (err) {
      setError(`Failed to render QR (${err.message || err}).`, name);
    }
  }

  document.querySelectorAll('.btn-qrcode').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      const name = btn.getAttribute('data-name') || '';
      if (name) showQr(name);
    });
  });
});