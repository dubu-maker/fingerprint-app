(function () {
  function initProgressForm(form) {
    const targetSelector = form.getAttribute('data-progress-target');
    if (!targetSelector) {
      return;
    }
    const container = document.querySelector(targetSelector);
    if (!container) {
      return;
    }
    const progressBar = container.querySelector('.progress-bar');
    const statusText = container.querySelector('.progress-status');
    const startMessage = form.getAttribute('data-progress-start') || '';
    const completeMessage = form.getAttribute('data-progress-complete') || '';

    form.addEventListener('submit', function handleSubmit(event) {
      if (!(window.XMLHttpRequest && 'upload' in new XMLHttpRequest())) {
        return;
      }
      event.preventDefault();
      const xhr = new XMLHttpRequest();
      const method = (form.method || 'POST').toUpperCase();
      const action = form.action;
      const formData = new FormData(form);

      container.classList.remove('d-none');
      updateProgress(0, startMessage);

      xhr.upload.addEventListener('progress', function (e) {
        if (!e.lengthComputable) {
          return;
        }
        const percent = Math.round((e.loaded / e.total) * 100);
        updateProgress(percent);
      });

      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 400) {
          updateProgress(100, completeMessage || null);
          const redirectUrl = xhr.responseURL || action;
          window.location.href = redirectUrl;
        } else {
          window.location.reload();
        }
      });

      xhr.addEventListener('error', function () {
        window.location.reload();
      });

      xhr.open(method, action);
      xhr.responseType = 'document';
      xhr.send(formData);

      function updateProgress(value, message) {
        if (progressBar) {
          progressBar.style.width = value + '%';
          progressBar.setAttribute('aria-valuenow', value.toString());
          progressBar.textContent = value + '%';
        }
        if (message && statusText) {
          statusText.textContent = message;
        }
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form[data-progress]').forEach(initProgressForm);
  });
})();
