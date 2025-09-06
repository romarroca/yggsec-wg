document.addEventListener('DOMContentLoaded', () => {
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(el => {
    setTimeout(() => {
      const inst = bootstrap.Alert.getOrCreateInstance(el);
      inst.close();
    }, 4000);
  });
});