/* TrustVault — progressive enhancement JS */

// Confirm destructive actions
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-confirm]').forEach(form => {
    form.addEventListener('submit', e => {
      if (!confirm(form.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });

  // Also attach confirm to delete buttons that don't use data-confirm on the form
  const deleteForm = document.getElementById('delete-form');
  if (deleteForm && !deleteForm.dataset.confirm) {
    deleteForm.addEventListener('submit', e => {
      if (!confirm('Permanently delete this document? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  // Disable submit button on login form to prevent double-submit
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', () => {
      const btn = document.getElementById('login-submit-btn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Verifying…';
      }
    });
  }

  // Upload form: show spinner
  const uploadForm = document.getElementById('upload-form');
  if (uploadForm) {
    uploadForm.addEventListener('submit', () => {
      const btn = document.getElementById('upload-submit-btn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Uploading…';
      }
    });

    const zone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('doc-file');
    const label = document.getElementById('upload-label');
    const updateLabel = () => {
      if (fileInput.files && fileInput.files[0]) {
        label.textContent = fileInput.files[0].name;
        zone.classList.add('has-file');
      }
    };

    fileInput.addEventListener('change', updateLabel);
    zone.addEventListener('dragover', event => {
      event.preventDefault();
      zone.classList.add('dragging');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragging'));
    zone.addEventListener('drop', event => {
      event.preventDefault();
      zone.classList.remove('dragging');
      if (event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        updateLabel();
      }
    });
  }
});