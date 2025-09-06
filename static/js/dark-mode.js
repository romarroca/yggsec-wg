(function () {
  const body = document.body;
  const btn  = document.getElementById('darkModeToggle');
  function updateBtn() {
    const dark = body.classList.contains('theme-dark');
    if (btn) btn.innerHTML = dark ? '<i class="bi bi-sun"></i> Light' : '<i class="bi bi-moon-stars"></i> Dark';
  }
  const saved = localStorage.getItem('darkMode');
  const firstVisit = (saved === null);
  const shouldBeDark = firstVisit ? true : (saved === 'true');
  if (shouldBeDark) body.classList.add('theme-dark');
  if (firstVisit) localStorage.setItem('darkMode', 'true');
  updateBtn();
  btn && btn.addEventListener('click', () => {
    body.classList.toggle('theme-dark');
    localStorage.setItem('darkMode', body.classList.contains('theme-dark'));
    updateBtn();
  });
})();