(() => {
  'use strict';

  // Las operaciones sensibles no se envían por HTTP: pasan por el objeto
  // nativo 'aegis', que exige elevación real. La SPA no posee credenciales.
  const privilegedRoutes = [
    { method: 'POST', re: /^\/api\/firewall\/rules\/?$/, op: 'FirewallAddRule',
      payload: (_, body) => ({ spec: body }) },
    { method: 'DELETE', re: /^\/api\/firewall\/rules\/(.+)$/, op: 'FirewallRemoveRule',
      payload: m => ({ name: decodeURIComponent(m[1]) }) },
    { method: 'POST', re: /^\/api\/quarantine\/([^/]+)\/restore\/?$/, op: 'QuarantineRestore',
      payload: m => ({ id: decodeURIComponent(m[1]) }) },
    { method: 'DELETE', re: /^\/api\/quarantine\/([^/]+)\/?$/, op: 'QuarantinePurge',
      payload: m => ({ id: decodeURIComponent(m[1]) }) },
    { method: 'PUT', re: /^\/api\/settings\/?$/, op: 'PolicyChange',
      payload: (_, body) => ({ policy: body }) }
  ];

  async function privilegedCall(operation, payload) {
    const bridge = window.chrome && window.chrome.webview &&
      window.chrome.webview.hostObjects && window.chrome.webview.hostObjects.aegis;
    if (!bridge) throw new Error('El puente privilegiado no está disponible; use la aplicación de escritorio.');
    const raw = await bridge.invoke(operation, JSON.stringify(payload));
    const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (data && data.ok === false) throw new Error(data.error || 'Operación rechazada.');
    return data;
  }
  const state = {
    health: null,
    status: null,
    events: [],
    threats: [],
    rules: [],
    ruleStats: null,
    quarantine: [],
    learned: [],
    settings: null,
    view: 'dashboard',
    threatFilter: 'all'
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  const esc = (value) => String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

  const KIND = {
    FileCreated: 'Archivo creado', FileModified: 'Archivo modificado', ProcessStarted: 'Proceso iniciado',
    NetworkConnection: 'Conexión de red', DnsQuery: 'Consulta DNS', RegistryChanged: 'Registro modificado',
    ServiceChanged: 'Servicio modificado', PersistenceChanged: 'Persistencia', ManualScan: 'Análisis manual'
  };
  const VERDICT = {
    Allow: ['Permitido', 'good'], Monitor: ['Monitorizar', 'info'],
    Block: ['Bloqueado', 'warn'], Quarantine: ['Cuarentena', 'bad']
  };
  const SEVERITY = {
    Info: ['info', 'info'], Low: ['baja', 'info'], Medium: ['media', 'warn'],
    High: ['alta', 'warn'], Critical: ['crítica', 'bad']
  };
  const SIGNATURE = {
    SignedTrusted: 'Firma válida', SignedUntrusted: 'Firma no válida', Unsigned: 'Sin firma',
    ChainNotVerifiable: 'Cadena no verificable', NotApplicable: 'No aplicable', Unknown: 'Desconocida'
  };

  const TITLES = {
    dashboard: ['Resumen de protección', 'Centro de mando'],
    analysis: ['Análisis bajo demanda', 'Inspección'],
    firewall: ['Firewall inteligente', 'Control de red'],
    threats: ['Amenazas detectadas', 'Centro de amenazas'],
    quarantine: ['Cuarentena', 'Recuperación segura'],
    history: ['Historial de actividad', 'Trazabilidad'],
    settings: ['Configuración', 'Políticas verificables'],
    help: ['Entender AEGIS Guard', 'Ayuda rápida']
  };

  async function api(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    for (const route of privilegedRoutes) {
      if (route.method !== method) continue;
      const match = path.match(route.re);
      if (!match) continue;
      const body = options.body ? JSON.parse(options.body) : {};
      const payload = route.payload ? route.payload(match, body) : body;
      return privilegedCall(route.op, payload);
    }

    const headers = { Accept: 'application/json', ...(options.headers || {}) };
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { ...options, headers, cache: 'no-store' });
    if (response.status === 403) {
      throw new Error('Acceso denegado: la interfaz debe abrirse desde 127.0.0.1.');
    }
    if (!response.ok) {
      let detail = '';
      try { detail = (await response.json()).error || ''; } catch { /* cuerpo no JSON */ }
      throw new Error(detail || `Error HTTP ${response.status}`);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  function toast(message, isError = false) {
    const node = document.createElement('div');
    node.className = `toast${isError ? ' error' : ''}`;
    node.textContent = message;
    $('#toastRegion').append(node);
    setTimeout(() => node.remove(), 4800);
  }

  function time(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('es-ES', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }

  const sevValue = (value) => typeof value === 'number'
    ? value : Math.max(0, Object.keys(SEVERITY).indexOf(value));
  const number = (value) => typeof value === 'number' ? value.toLocaleString('es-ES') : '—';
  const pct = (value) => typeof value === 'number' ? `${Math.round(value * 100)}%` : '—';
  const pill = (text, tone) => `<span class="pill ${tone}">${esc(text)}</span>`;
  const emptyRow = (columns, text) => `<tr class="empty-row"><td colspan="${columns}">${esc(text)}</td></tr>`;

  function detailOf(item) {
    const o = item?.observation || item;
    if (!o) return '—';
    if (o.kind === 'DnsQuery' || o.kind === 4) return o.subject;
    if (o.remoteAddress) return `${o.subject || ''} → ${o.remoteAddress}${o.remotePort ? ':' + o.remotePort : ''}`;
    return o.subject || '—';
  }

  function switchView(view) {
    if (!TITLES[view]) return;
    state.view = view;
    $$('.nav-item').forEach((button) => {
      const active = button.dataset.view === view;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    $$('.view').forEach((section) => section.classList.toggle('active', section.id === `view-${view}`));
    $('#viewTitle').textContent = TITLES[view][0];
    document.querySelector('.topbar .eyebrow').textContent = TITLES[view][1];
    if (view === 'dashboard') drawChart();
  }

  function renderStatus() {
    const s = state.status;
    if (!s) return;
    const labels = {
      protected: ['Protección activa', 'La monitorización, el firewall y las reglas locales están operativos.', 'good'],
      learning: ['Modo aprendizaje', 'El motor está observando actividad nueva sin bloquearla automáticamente.', 'info'],
      limited: ['Protección limitada', 'La monitorización funciona, pero el firewall de Windows no está disponible.', 'warn'],
      degraded: ['Motor degradado', s.etwActive === false
        ? 'ETW no está disponible: se usa sondeo de procesos y watchers. Revise los permisos del servicio.'
        : s.monitorActive === false
          ? 'La monitorización en tiempo real no está activa. Revise los permisos del servicio.'
          : 'Se descartaron eventos o hay sensores degradados; la visibilidad no es completa.', 'bad'],
      starting: ['Iniciando motor…', 'Comprobando monitorización, firewall y reglas locales.', 'warn']
    };
    const [heroTitle, heroDescription, tone] = labels[s.protectionState] || labels.starting;
    $('#heroTitle').textContent = heroTitle;
    $('#heroDescription').textContent = heroDescription;
    $('#engineText').textContent = s.monitorActive
      ? (s.managedByScm ? `Motor activo · ${s.serviceName || 'servicio SCM'}` : 'Motor activo')
      : 'Motor inactivo';
    $('#engineDot').className = `dot ${s.monitorActive ? 'online' : 'offline'}`;
    $('#navThreatCount').textContent = number(s.threatsTotal);
    $('#kpiEvents').textContent = number(s.eventsTotal);
    $('#kpiThreats').textContent = number(s.threatsTotal);
    if (state.ruleStats) $('#kpiBlocks').textContent = number(state.ruleStats.active);
    if ($('#kpiActions')) $('#kpiActions').textContent =
      `${number(s.blockedTotal || 0)} / ${number(s.quarantinedTotal || 0)}`;
    $('#kpiResources').textContent = `${number(s.cpuPercent)}% / ${Math.round((s.workingSetBytes || 0) / 1048576)} MB`;
    if (state.health && $('#versionLabel')) $('#versionLabel').textContent =
      `v${state.health.version || '3.0.0'} · motor local`;

    const tags = [
      ['Monitorización', s.monitorActive, 'good'],
      ['ETW', s.etwActive, s.etwActive ? 'good' : 'warn'],
      ['Firewall WFP', s.firewallActive, s.firewallActive ? 'good' : 'warn'],
      ['Servicio SCM', !!s.managedByScm, s.managedByScm ? 'good' : 'warn'],
      ['Sin pérdida de eventos', (s.droppedEvents || 0) === 0 && !s.queueSaturated && !s.watchersDegraded,
        (s.droppedEvents || 0) === 0 && !s.queueSaturated && !s.watchersDegraded ? 'good' : 'warn'],
      ['Motor local', s.monitorActive, 'good'],
      ['Inteligencia', (s.intelStatus === 'bundled' || String(s.intelStatus || '').startsWith('verified:')),
        (s.intelStatus === 'bundled' || String(s.intelStatus || '').startsWith('verified:')) ? 'good' : 'warn'],
      ['Modo aprendizaje', !!s.policy?.learningMode, 'warn']
    ];
    $('#heroTags').innerHTML = tags.map(([label, ok, cls]) =>
      `<span class="tag ${ok ? cls : ''}">${esc(label)}: ${ok ? 'sí' : 'no'}</span>`).join('');

    const avg = Array.isArray(s.riskTrend) && s.riskTrend.length
      ? s.riskTrend.reduce((a, b) => a + b, 0) / s.riskTrend.length : 0;
    $('#shieldLabel').textContent = s.riskTrend?.length ? `Riesgo medio ${Math.round(avg)}` : 'Sin eventos aún';
    const ring = $('#riskRing');
    ring.style.strokeDashoffset = String(515 - 515 * Math.min(1, avg / 100));
    ring.style.stroke = tone === 'bad' ? 'var(--danger)' : tone === 'warn' ? 'var(--warn)' : 'var(--accent)';

    const steps = [
      ['Motor en tiempo real', s.monitorActive],
      ['Telemetría ETW', s.etwActive, 'ETW no disponible; se usa sondeo de procesos'],
      ['Firewall de Windows disponible', s.firewallActive],
      ['Servicio automático del sistema', !!s.managedByScm,
        s.managedByScm ? 'Registrado en el SCM' : 'Ejecución manual; use finish.cmd para registrarlo'],
      ['Inteligencia local íntegra', s.intelStatus === 'bundled' || String(s.intelStatus || '').startsWith('verified:'),
        `Fuentes: ${s.intelStatus || 'sin cargar'} · hashes ${number(s.intelHashCount || 0)} · reglas ${number(s.yaraRuleCount || 0)}`],
      ['Eventos observados', (s.eventsTotal || 0) > 0],
      ['Sin pérdida de visibilidad', (s.droppedEvents || 0) === 0 && !s.watchersDegraded && !s.queueSaturated,
        'Se descartaron eventos o un watcher dejó de informar'],
      ['Amenazas revisadas', (s.threatsTotal || 0) > 0]
    ];
    $('#wizardList').innerHTML = steps.map(([label, done, pending]) =>
      `<li class="${done ? 'done' : ''}"><span class="step-icon">${done
        ? '<svg><use href="#i-check"/></svg>' : '·'}</span><span><strong>${esc(label)}</strong>${
        done ? 'Comprobado con datos del servicio' : esc(pending || 'Pendiente; se actualizará automáticamente')}</span></li>`).join('');

    const unreviewed = state.threats.filter((t) => !t.remediated &&
      (t.decision?.severity === 'Critical' || t.decision?.severity === 4)).length;
    $('#notifDot').hidden = unreviewed === 0;
    $('#notificationBtn').title = unreviewed
      ? `${unreviewed} amenaza(s) crítica(s) sin remediar` : 'Sin notificaciones pendientes';
  }

  function drawChart() {
    const canvas = $('#riskChart');
    const values = state.status?.riskTrend || [];
    const empty = $('#emptyChart');
    empty.hidden = values.length > 0;
    const ratio = window.devicePixelRatio || 1;
    const width = canvas.clientWidth, height = canvas.clientHeight;
    canvas.width = Math.max(1, Math.floor(width * ratio));
    canvas.height = Math.max(1, Math.floor(height * ratio));
    const ctx = canvas.getContext('2d');
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);
    if (!values.length) return;

    const styles = getComputedStyle(document.documentElement);
    const grid = styles.getPropertyValue('--border-soft').trim() || '#1d293b';
    const accent = styles.getPropertyValue('--accent').trim() || '#39e6c3';
    const pad = 12;
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad + (height - pad * 2) * i / 4;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    const points = values.map((v, i) => ({
      x: pad + (width - pad * 2) * i / Math.max(1, values.length - 1),
      y: height - pad - (height - pad * 2) * Math.min(100, Math.max(0, v)) / 100
    }));
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, accent + '55');
    gradient.addColorStop(1, accent + '00');
    ctx.beginPath();
    ctx.moveTo(points[0].x, height - pad);
    points.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.lineTo(points[points.length - 1].x, height - pad);
    ctx.closePath(); ctx.fillStyle = gradient; ctx.fill();
    ctx.beginPath();
    points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
    ctx.strokeStyle = accent; ctx.lineWidth = 2; ctx.stroke();
    points.forEach((p) => {
      ctx.beginPath(); ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = accent; ctx.fill();
    });
  }

  function decisionPill(decision) {
    const verdict = decision?.verdict;
    const [label, tone] = VERDICT[verdict] || (decision ? ['Evaluado', 'info'] : ['Observado', 'info']);
    return pill(label, tone);
  }

  function renderEvents() {
    const rows = state.events.slice(0, 12).map((o) =>
      `<tr><td>${esc(time(o.timestamp))}</td><td>${esc(KIND[o.kind] || o.kind)}</td>
       <td>${esc(o.source)}</td><td class="mono">${esc(detailOf(o)).slice(0, 120)}</td>
       <td>${decisionPill(o.decision)}</td></tr>`).join('');
    $('#recentBody').innerHTML = rows.length ? rows : emptyRow(5, 'Aún no hay eventos registrados.');

    $('#historyBody').innerHTML = state.events.length ? state.events.map((o) =>
      `<tr><td>${esc(time(o.timestamp))}</td><td>${esc(KIND[o.kind] || o.kind)}</td>
       <td>${esc(o.source)}</td><td class="mono">${esc(detailOf(o)).slice(0, 160)}</td>
       <td class="mono">${esc((o.sha256 || '—').slice(0, 16))}</td>
       <td>${decisionPill(o.decision)}</td></tr>`).join('')
      : emptyRow(6, 'Aún no hay eventos registrados.');
  }

  function renderThreats() {
    const filtered = state.threats.filter((t) => {
      if (state.threatFilter === 'all') return true;
      const s = sevValue(t.decision?.severity);
      return state.threatFilter === 'Critical' ? s >= 4
        : state.threatFilter === 'High' ? s >= 3 : s === 2;
    });
    const rows = filtered.map((t) => {
      const d = t.decision || {};
      const [sev, tone] = SEVERITY[d.severity] || [String(d.severity ?? '—'), 'info'];
      const [verdict, vtone] = VERDICT[d.verdict] || [String(d.verdict ?? '—'), 'info'];
      return `<tr><td>${esc(time(t.timestamp))}</td><td><strong>${esc(detailOf(t)).slice(0, 100)}</strong></td>
        <td>${pill(sev, tone)}</td><td>${pill(verdict, vtone)}</td>
        <td>${esc(number(d.risk))}</td>
        <td><button class="btn tiny" data-detail="${esc(t.id)}">Detalle</button></td></tr>`;
    });
    $('#threatsBody').innerHTML = rows.length ? rows.join('') : emptyRow(6, 'No hay amenazas con este filtro.');
    $$('[data-detail]').forEach((button) => button.addEventListener('click', () =>
      showThreatDetail(button.dataset.detail)));
  }

  function showThreatDetail(id) {
    const t = state.threats.find((x) => x.id === id);
    if (!t) return;
    state.lastDetail = id;
    const o = t.observation || {}, d = t.decision || {};
    const reasons = (d.reasons || []).map((r) => `<li>${esc(r)}</li>`).join('') || '<li>Sin motivos registrados</li>';
    const flags = (o.behaviorFlags || []).map((f) => pill(f, 'warn')).join(' ');
    $('#threatDetail').hidden = false;
    $('#threatDetail').innerHTML = `<span class="eyebrow">Hallazgo ${esc(t.id.slice(0, 12))}</span>
      <h3>${esc(detailOf(t))}</h3>
      <div class="score-layout">
        <div class="score-block"><span>Riesgo</span><strong>${esc(number(d.risk))}/100</strong></div>
        <div class="score-block"><span>Confianza</span><strong>${esc(pct(d.confidence))}</strong></div>
        <div class="score-block"><span>Evidencias</span><strong>${esc(number(d.local?.evidenceCount))}</strong><small>señales locales verificadas</small></div>
      </div>
      <div class="evidence"><h4>Motivos de la decisión</h4><ul>${reasons}</ul></div>
      <dl class="meta-list">
        <div><dt>Reglas locales</dt><dd>${esc((o.ruleMatches || []).map((r) => r.ruleId).join(', ') || 'ninguna')}</dd></div>
        <div><dt>Indicadores</dt><dd>${flags || 'ninguno'}</dd></div>
        <div><dt>Firma</dt><dd>${esc(SIGNATURE[o.signature] || o.signature || '—')}</dd></div>
        <div><dt>Hash SHA-256</dt><dd class="mono">${esc(o.sha256 || '—')}</dd></div>
        <div><dt>Remediación</dt><dd>${esc(t.remediationDetail || (t.remediated ? 'aplicada' : 'sin acción automática'))}</dd></div>
        <div><dt>Origen</dt><dd>${esc(o.source || '—')}</dd></div>
      </dl>`;
    $('#threatDetail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderFirewall() {
    $('#rulesBody').innerHTML = state.rules.length ? state.rules.map((name) =>
      `<tr><td><strong>${esc(name)}</strong></td>
       <td><button class="btn tiny danger" data-remove-rule="${esc(name)}">Eliminar</button></td></tr>`).join('')
      : emptyRow(2, 'No hay reglas AEGIS creadas en el firewall de Windows.');
    const stats = state.ruleStats;
    if (stats) {
      const small = document.querySelector('#kpiBlocks').closest('.kpi').querySelector('small');
      small.textContent = `${number(stats.automatic)} automáticas / ${number(stats.manual)} manuales`;
    }
    $$('[data-remove-rule]').forEach((button) => button.addEventListener('click', async () => {
      try {
        await api('/api/firewall/rules/' + encodeURIComponent(button.dataset.removeRule), { method: 'DELETE' });
        toast('Regla eliminada del firewall');
        await loadFirewall();
      } catch (error) { toast(error.message, true); }
    }));

    $('#learnedBody').innerHTML = state.learned.length ? state.learned.map((c) =>
      `<tr><td class="mono">${esc(c.endpoint)}</td><td>${esc(number(c.observations))}</td></tr>`).join('')
      : emptyRow(2, 'El modo aprendizaje aún no ha observado conexiones.');
  }

  function renderQuarantine() {
    $('#quarantineBody').innerHTML = state.quarantine.length ? state.quarantine.map((q) =>
      `<tr><td>${esc(time(q.timestamp))}</td><td class="mono">${esc(q.originalPath)}</td>
       <td>${esc(q.reason)}</td><td>
       <button class="btn tiny" data-restore="${esc(q.id)}" ${q.restored ? 'disabled' : ''}>Restaurar</button>
       <button class="btn tiny danger" data-purge="${esc(q.id)}">Eliminar</button></td></tr>`).join('')
      : emptyRow(4, 'La cuarentena está vacía.');
    $$('[data-restore]').forEach((button) => button.addEventListener('click', async () => {
      try {
        await api(`/api/quarantine/${encodeURIComponent(button.dataset.restore)}/restore`, { method: 'POST' });
        toast('Archivo restaurado en su ruta original');
        await loadQuarantine();
      } catch (error) { toast(error.message, true); }
    }));
    $$('[data-purge]').forEach((button) => button.addEventListener('click', async () => {
      if (!confirm('¿Eliminar definitivamente este elemento de la cuarentena?')) return;
      try {
        await api('/api/quarantine/' + encodeURIComponent(button.dataset.purge), { method: 'DELETE' });
        toast('Elemento eliminado definitivamente');
        await loadQuarantine();
      } catch (error) { toast(error.message, true); }
    }));
  }

  function renderScan() {
    const box = $('#scanResult');
    if (!state.scanResult) { box.hidden = true; return; }
    box.hidden = false;
    const d = state.scanResult.decision || {}, o = state.scanResult.observation || {};
    const [verdict] = VERDICT[d.verdict] || [String(d.verdict ?? '—')];
    const [sev, tone] = SEVERITY[d.severity] || [String(d.severity ?? '—'), 'info'];
    $('#scanVerdict').textContent = verdict;
    $('#scanSeverity').textContent = sev;
    $('#scanSeverity').className = `severity-pill pill ${tone}`;
    $('#scanRisk').textContent = `${number(d.risk)}/100`;
    $('#scanRiskBar').style.width = `${Math.min(100, Number(d.risk) || 0)}%`;
    $('#scanConfidence').textContent = pct(d.confidence);
    $('#scanConfidenceBar').style.width = `${Math.round((Number(d.confidence) || 0) * 100)}%`;
    $('#scanEvidence').textContent = number(d.local?.evidenceCount);
    $('#scanEvidenceDetail').textContent = `${(o.ruleMatches || []).length} regla(s) local(es)`;
    $('#scanReasons').innerHTML = (d.reasons || []).map((r) => `<li>${esc(r)}</li>`).join('') || '<li>Sin motivos registrados</li>';
    const entries = [
      ['SHA-256', o.sha256], ['Tamaño', typeof o.fileSize === 'number' ? `${number(o.fileSize)} bytes` : '—'],
      ['Firma', SIGNATURE[o.signature]], ['Reglas', (o.ruleMatches || []).map((r) => r.ruleId).join(', ')],
      ['Remediación', state.scanResult.remediationDetail || 'sin acción automática']
    ];
    $('#scanMeta').innerHTML = entries.map(([key, value]) =>
      `<div><dt>${esc(key)}</dt><dd>${esc(value || '—')}</dd></div>`).join('');
  }

  function renderSettings() {
    const p = state.settings;
    if (!p) return;
    $('#setLearning').checked = !!p.learningMode;
    $('#setQuarantine').checked = !!p.autoQuarantine;
    $('#setBlock').checked = !!p.autoBlockNetwork;
    const ranges = [
      ['setMonitor', 'outMonitor', p.monitorThreshold],
      ['setBlockThreshold', 'outBlock', p.blockThreshold],
      ['setQuarantineThreshold', 'outQuarantine', p.quarantineThreshold]
    ];
    ranges.forEach(([input, output, value]) => {
      $('#' + input).value = value;
      $('#' + output).textContent = `${value}/100`;
    });
    $$('input[type=range]').forEach((input) => input.addEventListener('input', () => {
      const output = $(`#out${{ setMonitor: 'Monitor', setBlockThreshold: 'Block', setQuarantineThreshold: 'Quarantine' }[input.id]}`);
      if (output) output.textContent = `${input.value}/100`;
    }));
  }

  // Los sondeos periódicos no deben acumularse si una respuesta tarda más que
  // el intervalo; una sola petición en vuelo por conjunto de datos evita
  // sobrecargar el servicio y reemplazar datos frescos por respuestas obsoletas.
  const inFlight = { core: false, firewall: false, quarantine: false };

  async function loadCore() {
    if (inFlight.core) return;
    inFlight.core = true;
    try {
      const [status, health, events, threats] = await Promise.all([
        api('/api/status'), api('/api/health'), api('/api/events?limit=200'), api('/api/threats?limit=200')
      ]);
      state.status = status;
      state.health = health;
      state.events = events;
      state.threats = threats;
      renderStatus(); renderEvents(); renderThreats();
      if (state.view === 'dashboard') drawChart();
      if ($('#threatDetail').hidden === false && state.lastDetail) showThreatDetail(state.lastDetail);
    } catch (error) { toast(error.message, true); }
    finally { inFlight.core = false; }
  }

  async function loadFirewall() {
    if (inFlight.firewall) return;
    inFlight.firewall = true;
    try {
      const [rules, learned, stats] = await Promise.all([
        api('/api/firewall/rules'), api('/api/firewall/learned'), api('/api/firewall/stats')
      ]);
      state.rules = rules; state.learned = learned; state.ruleStats = stats;
      renderFirewall();
      if (state.status) renderStatus();
    } catch (error) { toast(error.message, true); }
    finally { inFlight.firewall = false; }
  }

  async function loadQuarantine() {
    if (inFlight.quarantine) return;
    inFlight.quarantine = true;
    try {
      state.quarantine = await api('/api/quarantine');
      renderQuarantine();
    } catch (error) { toast(error.message, true); }
    finally { inFlight.quarantine = false; }
  }

  async function loadSettings() {
    try {
      state.settings = await api('/api/settings');
      renderSettings();
    } catch (error) { toast(error.message, true); }
  }

  function bind() {
    $$('.nav-item').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
    $$('[data-go]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.go)));

    const theme = localStorage.getItem('aegis-theme') || 'dark';
    document.documentElement.dataset.theme = theme;
    $('#themeToggle').innerHTML = `<svg><use href="#i-${theme === 'dark' ? 'sun' : 'moon'}"/></svg>`;
    $('#themeToggle').addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      localStorage.setItem('aegis-theme', next);
      $('#themeToggle').innerHTML = `<svg><use href="#i-${next === 'dark' ? 'sun' : 'moon'}"/></svg>`;
      drawChart();
    });

    $('#notificationBtn').addEventListener('click', () => switchView('threats'));

    $('#scanBtn').addEventListener('click', async () => {
      const path = $('#scanPath').value.trim();
      if (!path) { toast('Escribe la ruta completa del archivo', true); return; }
      $('#scanBtn').disabled = true;
      try {
        state.scanResult = await api('/api/scan', { method: 'POST', body: JSON.stringify({ path }) });
        renderScan();
        toast('Análisis completado');
        await loadCore();
      } catch (error) { toast(error.message, true); }
      finally { $('#scanBtn').disabled = false; }
    });
    $('#scanPath').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#scanBtn').click(); });

    $('#addRuleBtn').addEventListener('click', async () => {
      const port = Number($('#fwPort').value);
      const spec = {
        name: '', block: true, inbound: false,
        applicationPath: $('#fwApp').value.trim() || null,
        remoteAddresses: $('#fwIp').value.trim() || null,
        protocol: Number($('#fwProtocol').value),
        remotePort: port >= 1 && port <= 65535 ? port : null,
        description: 'Regla creada desde AEGIS Guard'
      };
      try {
        await api('/api/firewall/rules', { method: 'POST', body: JSON.stringify(spec) });
        toast('Regla añadida al firewall de Windows');
        $('#fwApp').value = ''; $('#fwIp').value = ''; $('#fwPort').value = '';
        await loadFirewall();
      } catch (error) { toast(error.message, true); }
    });
    $('#refreshRules').addEventListener('click', async () => { await loadFirewall(); toast('Reglas actualizadas'); });
    $('#threatFilter').addEventListener('change', (event) => { state.threatFilter = event.target.value; renderThreats(); });

    $('#exportBtn').addEventListener('click', async () => {
      try {
        // La tabla solo carga 200 eventos para ser ágil; la exportación
        // recorre todas las páginas hasta agotar el historial.
        const page = 1000;
        const events = [];
        for (let skip = 0; skip < 100000; skip += page) {
          const batch = await api(`/api/events?limit=${page}&skip=${skip}`);
          events.push(...batch);
          if (batch.length < page) break;
        }
        const payload = { exportedAt: new Date().toISOString(), count: events.length, events };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `aegis-eventos-${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        URL.revokeObjectURL(url);
        toast(`${number(events.length)} eventos exportados`);
      } catch (error) { toast(error.message, true); }
    });

    $('#saveSettings').addEventListener('click', async () => {
      const policy = {
        learningMode: $('#setLearning').checked,
        autoQuarantine: $('#setQuarantine').checked,
        autoBlockNetwork: $('#setBlock').checked,
        monitorThreshold: Number($('#setMonitor').value),
        blockThreshold: Number($('#setBlockThreshold').value),
        quarantineThreshold: Number($('#setQuarantineThreshold').value),
        maxEvents: state.settings?.maxEvents || 500
      };
      try {
        const applied = await api('/api/settings', { method: 'PUT', body: JSON.stringify(policy) });
        const adjusted = ['monitorThreshold', 'blockThreshold', 'quarantineThreshold', 'maxEvents']
          .some((key) => applied[key] !== policy[key]);
        state.settings = applied;
        renderSettings();
        toast(adjusted ? 'Configuración guardada; algunos valores se ajustaron a límites seguros' : 'Configuración guardada y aplicada');
        await loadCore();
      } catch (error) { toast(error.message, true); }
    });

    $('#runEicar').addEventListener('click', async () => {
      const result = $('#eicarResult');
      result.hidden = false;
      result.textContent = 'Ejecutando prueba con el motor local…';
      try {
        const test = await api('/api/selftest/eicar', { method: 'POST' });
        if (test.detected) {
          result.textContent = `Detectado por AEGIS Guard: ${test.verdict}, riesgo ${Math.round(test.risk)}. ${test.detail}`;
          toast('Prueba EICAR detectada por el motor local');
        } else if (test.fileBlockedExternally) {
          result.textContent = test.detail;
          toast('La muestra fue bloqueada antes del análisis; no desactive otros antivirus', true);
        } else {
          result.textContent = `El motor no detectó la muestra (${test.verdict}). Revise las reglas instaladas.`;
          toast('Prueba EICAR no detectada', true);
        }
      } catch (error) {
        result.textContent = error.message;
        toast(error.message, true);
      }
    });

    window.addEventListener('resize', () => { if (state.view === 'dashboard') drawChart(); });
  }

  bind();
  loadCore();
  loadFirewall();
  loadQuarantine();
  loadSettings();
  setInterval(() => { if (state.view === 'dashboard' || state.view === 'threats') loadCore(); }, 4000);
  setInterval(loadFirewall, 15000);
  setInterval(loadQuarantine, 15000);
})();
