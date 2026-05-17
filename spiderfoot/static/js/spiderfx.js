(function() {
  function updateStats() {
    fetch((window.docroot || '') + '/fxhealth', { cache: 'no-store' })
      .then(function(res) {
        if (!res.ok) {
          throw new Error('fxhealth unavailable');
        }
        return res.json();
      })
      .then(function(data) {
        var total = document.getElementById('fx-stat-total');
        var active = document.getElementById('fx-stat-active');
        var modules = document.getElementById('fx-stat-modules');
        if (total) total.textContent = data.scans_total;
        if (active) active.textContent = data.scans_active;
        if (modules) modules.textContent = data.modules_total;
      })
      .catch(function() {
        // Keep defaults if API is unavailable.
      });
  }

  function smoothAnchors() {
    var links = document.querySelectorAll('a[href^="#"]');
    links.forEach(function(link) {
      link.addEventListener('click', function(evt) {
        var href = link.getAttribute('href');
        if (!href || href.length < 2) {
          return;
        }
        var target = document.querySelector(href);
        if (!target) {
          return;
        }
        evt.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function() {
    updateStats();
    smoothAnchors();
  });
})();
