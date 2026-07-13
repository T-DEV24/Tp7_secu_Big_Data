const dashboardCharts = {};

function colorForRisk(level) {
  const normalized = String(level || '').toLowerCase();
  if (normalized.includes('élev') || normalized.includes('elev')) return '#dc2626';
  if (normalized.includes('moy')) return '#f97316';
  return '#16a34a';
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`Erreur HTTP ${response.status} pour ${url}`);
  return response.json();
}

function showDashboardError(message) {
  const box = document.getElementById('dashboardError');
  if (!box) return;
  box.textContent = message;
  box.classList.remove('d-none');
}

function renderChart(id, config) {
  const element = document.getElementById(id);
  if (!element || !window.Chart) return;
  if (dashboardCharts[id]) dashboardCharts[id].destroy();
  dashboardCharts[id] = new Chart(element, config);
}

function entries(data) {
  return Object.entries(data || {});
}

function renderTopUsers(rows) {
  const tbody = document.querySelector('#topUsersTable tbody');
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Aucune alerte à risque élevé disponible.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map((row) => {
    const level = row.dominant_risk_level || 'élevé';
    return `<tr>
      <td>${row.user_id}</td>
      <td>${row.total_score}</td>
      <td>${row.alert_count}</td>
      <td>${row.last_reason || 'Non renseignée'}</td>
      <td><span class="badge" style="background:${colorForRisk(level)}">${level}</span></td>
      <td><a class="btn btn-sm btn-outline-primary" href="/users/${encodeURIComponent(row.user_id)}/alerts">Voir</a></td>
    </tr>`;
  }).join('');
}

async function loadDashboard() {
  try {
    const [summary, topUsers, byHour, byAction, byRisk, byDay, byDepartment] = await Promise.all([
      fetchJson('/api/dashboard/summary'),
      fetchJson('/api/dashboard/top-users?n=10'),
      fetchJson('/api/dashboard/timeseries?granularity=hour'),
      fetchJson('/api/dashboard/by-action'),
      fetchJson('/api/dashboard/by-risk-level'),
      fetchJson('/api/dashboard/timeseries?granularity=day'),
      fetchJson('/api/dashboard/by-department'),
    ]);

    document.getElementById('kpi24h').textContent = summary.alerts_24h;
    document.getElementById('kpi7d').textContent = summary.alerts_7d;
    document.getElementById('kpi30d').textContent = summary.alerts_30d;
    document.getElementById('kpiAverage').textContent = summary.average_score;
    document.getElementById('kpiTopUser').textContent = summary.top_user ? summary.top_user.user_id : 'Aucun';

    const hourEntries = entries(byHour);
    const actionEntries = entries(byAction).sort((a, b) => b[1] - a[1]);
    const riskEntries = entries(byRisk);
    const dayEntries = entries(byDay);
    const deptEntries = entries(byDepartment).sort((a, b) => b[1] - a[1]);

    renderChart('alertsByHourChart', { type: 'bar', data: { labels: hourEntries.map(([k]) => `${k}h`), datasets: [{ label: 'Alertes', data: hourEntries.map(([, v]) => v), backgroundColor: hourEntries.map(([, v]) => v > 3 ? '#dc2626' : '#f97316') }] }, options: { responsive: true, plugins: { legend: { display: false } } } });
    renderChart('alertsByActionChart', { type: 'bar', data: { labels: actionEntries.map(([k]) => k), datasets: [{ label: 'Alertes', data: actionEntries.map(([, v]) => v), backgroundColor: '#2563eb' }] }, options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } } });
    renderChart('riskLevelChart', { type: 'doughnut', data: { labels: riskEntries.map(([k]) => k), datasets: [{ data: riskEntries.map(([, v]) => v), backgroundColor: riskEntries.map(([k]) => colorForRisk(k)) }] }, options: { responsive: true } });
    renderChart('alertsByDayChart', { type: 'line', data: { labels: dayEntries.map(([k]) => k), datasets: [{ label: 'Alertes', data: dayEntries.map(([, v]) => v), borderColor: '#0f766e', tension: 0.25 }] }, options: { responsive: true } });
    renderChart('departmentChart', { type: 'bar', data: { labels: deptEntries.map(([k]) => k), datasets: [{ label: 'Alertes', data: deptEntries.map(([, v]) => v), backgroundColor: '#f97316' }] }, options: { responsive: true, plugins: { legend: { display: false } } } });
    renderTopUsers(topUsers);
  } catch (error) {
    showDashboardError(`Impossible de charger les indicateurs du dashboard : ${error.message}`);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  ['periodFilter', 'riskFilter', 'departmentFilter'].forEach((id) => document.getElementById(id)?.addEventListener('change', loadDashboard));
  loadDashboard();
});
