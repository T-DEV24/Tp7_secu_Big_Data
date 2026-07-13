document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.needs-validation').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    });
  });

  const otpInput = document.getElementById('otpInput');
  if (otpInput) {
    otpInput.addEventListener('input', () => {
      otpInput.value = otpInput.value.replace(/\D/g, '').slice(0, 6);
      if (otpInput.value.length === 6) {
        document.getElementById('otpForm').requestSubmit();
      }
    });

    const otpCountdownEl = document.getElementById('otpCountdown');
    const otpDuration = parseInt(otpCountdownEl && otpCountdownEl.dataset.otpSeconds, 10) || 300;
    let seconds = otpDuration;
    setInterval(() => {
      seconds = seconds <= 1 ? otpDuration : seconds - 1;
      const countdown = document.getElementById('otpCountdown');
      if (countdown) countdown.textContent = seconds;
    }, 1000);
  }


  document.querySelectorAll('[data-filter]').forEach((input) => {
    input.addEventListener('input', () => filterTable(input.dataset.filter));
  });

  document.querySelectorAll('[data-column-filter]').forEach((select) => {
    select.addEventListener('change', () => filterTable('resourceTable'));
  });

  renderChart('typeChart', 'bar', 'Accès');
  renderChart('denyChart', 'bar', 'Refus');
  animateCounters();
});

function filterTable(tableId) {
  const table = document.getElementById(tableId);
  if (!table || !table.tBodies.length) return;

  const query = (document.querySelector(`[data-filter="${tableId}"]`)?.value || '').toLowerCase();
  const columnFilters = Array.from(document.querySelectorAll('[data-column-filter]'));

  Array.from(table.tBodies[0].rows).forEach((row) => {
    let visible = row.innerText.toLowerCase().includes(query);
    columnFilters.forEach((select) => {
      const value = select.value;
      const cell = row.cells[Number(select.dataset.columnFilter)];
      if (value && cell?.innerText.trim() !== value) visible = false;
    });
    row.style.display = visible ? '' : 'none';
  });
}

function renderChart(elementId, type, label) {
  const element = document.getElementById(elementId);
  if (!element || !window.Chart) return;

  new Chart(element, {
    type,
    data: {
      labels: JSON.parse(element.dataset.labels || '[]'),
      datasets: [{
        label,
        data: JSON.parse(element.dataset.values || '[]'),
        backgroundColor: ['#0f766e', '#94a3b8', '#cbd5e1', '#64748b', '#334155'],
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
    },
  });
}

function animateCounters() {
  document.querySelectorAll('[data-counter]').forEach((element) => {
    const target = Number(element.dataset.counter);
    if (!Number.isFinite(target) || target <= 0) return;

    let current = 0;
    const step = Math.max(1, Math.ceil(target / 20));
    const timer = setInterval(() => {
      current += step;
      element.textContent = Math.min(current, target);
      if (current >= target) clearInterval(timer);
    }, 25);
  });
}
