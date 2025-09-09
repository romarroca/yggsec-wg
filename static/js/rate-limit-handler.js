// Rate limit error handler for YggSec
document.addEventListener('DOMContentLoaded', () => {
  // Create a global rate limit toast container
  function createRateLimitToast() {
    const toastContainer = document.getElementById('toast-container') || (() => {
      const container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container position-fixed top-0 end-0 p-3';
      container.style.zIndex = '1055';
      document.body.appendChild(container);
      return container;
    })();

    const toastHtml = `
      <div class="toast align-items-center text-bg-warning border-0" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="d-flex">
          <div class="toast-body">
            <i class="bi bi-exclamation-triangle me-2"></i>
            <strong>Request limit exceeded</strong><br>
            You are sending requests too quickly. Please wait a moment and try again.
          </div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
      </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = toastContainer.lastElementChild;
    const toast = new bootstrap.Toast(toastElement, { delay: 8000 });
    toast.show();

    // Remove toast element after it's hidden
    toastElement.addEventListener('hidden.bs.toast', () => {
      toastElement.remove();
    });
  }

  // Override fetch to handle rate limit errors globally
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    try {
      const response = await originalFetch.apply(this, args);
      
      if (response.status === 429) {
        // Handle rate limit error
        try {
          const data = await response.json();
          if (data.type === 'rate_limit') {
            createRateLimitToast();
            // Return a rejected promise to prevent further processing
            return Promise.reject(new Error('Rate limit exceeded'));
          }
        } catch (e) {
          // Fallback if response is not JSON
          createRateLimitToast();
          return Promise.reject(new Error('Rate limit exceeded'));
        }
      }
      
      return response;
    } catch (error) {
      // Re-throw non-rate-limit errors
      throw error;
    }
  };
});