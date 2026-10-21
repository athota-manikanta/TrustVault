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
  }
});