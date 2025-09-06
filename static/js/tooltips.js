function enableTooltips(scope=document){
  const nodes = [].slice.call(scope.querySelectorAll('[data-bs-toggle="tooltip"]'));
  nodes.forEach(el => {
    if (!bootstrap.Tooltip.getInstance(el)){
      new bootstrap.Tooltip(el, {
        container: 'body',
        trigger: 'hover focus',
        delay: {show:150, hide:50},
        customClass: 'cu-tooltip'
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', () => enableTooltips());
document.addEventListener('shown.bs.modal', e => enableTooltips(e.target));