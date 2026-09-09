(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem('csage-font-scale') || '100';
  root.style.setProperty('--font-scale', saved + '%');
  document.querySelectorAll('[data-font]').forEach(btn => btn.addEventListener('click', () => {
    const value = btn.dataset.font;
    root.style.setProperty('--font-scale', value + '%');
    localStorage.setItem('csage-font-scale', value);
  }));
  const contrast = localStorage.getItem('csage-high-contrast') === 'true';
  document.body.classList.toggle('high-contrast', contrast);
  const toggle = document.getElementById('contrastToggle');
  if (toggle) toggle.addEventListener('click', () => {
    document.body.classList.toggle('high-contrast');
    localStorage.setItem('csage-high-contrast', document.body.classList.contains('high-contrast'));
  });
})();
