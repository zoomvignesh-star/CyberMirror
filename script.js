let threatBreakdown = [
  { label: 'Critical', value: 0, color: '#ff6b7e' },
  { label: 'High', value: 0, color: '#ffb454' },
  { label: 'Medium', value: 0, color: '#32d1ff' },
  { label: 'Low', value: 0, color: '#3ed29a' }
];

const threats = [
  { name: 'Brute-force login', source: 'Finance VPN', severity: 'Critical', status: 'Detected', score: 94 },
  { name: 'SQL injection probe', source: 'Public web app', severity: 'High', status: 'Mitigated', score: 88 },
  { name: 'Phishing lure', source: 'Employee mailbox', severity: 'Medium', status: 'Monitoring', score: 71 },
  { name: 'Credential stuffing', source: 'Partner portal', severity: 'Critical', status: 'Detected', score: 96 },
  { name: 'Malware beaconing', source: 'Endpoint 42', severity: 'High', status: 'Mitigated', score: 82 }
];

const legendList = document.getElementById('legendList');
const donutChart = document.getElementById('donutChart');
const donutScore = document.getElementById('donutScore');
const donutLabel = document.getElementById('donutLabel');
const threatTableBody = document.getElementById('threatTableBody');
const authBackdrop = document.getElementById('authBackdrop');
const authForm = document.getElementById('authForm');
const authTitle = document.getElementById('authTitle');
const authDescription = document.getElementById('authDescription');
const authSubmit = document.getElementById('authSubmit');
const formMessage = document.getElementById('formMessage');
const loginButton = document.getElementById('loginButton');
const closeAuthButton = document.getElementById('closeAuthButton');
const loginTab = document.getElementById('loginTab');
const registerTab = document.getElementById('registerTab');
const reportsNavButton = document.getElementById('reportsNavButton');
const reportBackdrop = document.getElementById('reportBackdrop');
const closeReportButton = document.getElementById('closeReportButton');
const reportList = document.getElementById('reportList');
const reportThreatCount = document.getElementById('reportThreatCount');
const threatAnalyticsNavButton = document.getElementById('threatAnalyticsNavButton');
const threatAnalyticsSection = document.getElementById('threatAnalyticsSection');
const urlScannerForm = document.getElementById('urlScannerForm');
const urlInput = document.getElementById('urlInput');
const urlscanApiKey = document.getElementById('urlscanApiKey');
const scannerStatus = document.getElementById('scannerStatus');
const scanResult = document.getElementById('scanResult');
const recommendations = document.getElementById('recommendations');
const analyticsUrlScanResults = document.getElementById('analyticsUrlScanResults');
const reportUrlScanResults = document.getElementById('reportUrlScanResults');
let authMode = 'login';
const urlScanResults = [];

const preventionMethods = {
  'Brute-force login': 'Enforce MFA, rate-limit login attempts, and temporarily lock accounts after repeated failures.',
  'SQL injection probe': 'Patch the vulnerable input path and use parameterized queries with an updated WAF rule.',
  'Phishing lure': 'Quarantine the message, block the sender domain, and remind users to verify links before signing in.',
  'Credential stuffing': 'Require MFA, reject reused passwords, and monitor sign-in attempts from unfamiliar locations.',
  'Malware beaconing': 'Isolate the endpoint, block the command server, and run an endpoint malware investigation.'
};

function renderLegend() {
  legendList.innerHTML = threatBreakdown.map((item) => `
    <li>
      <span class="legend-name"><span class="swatch" style="background:${item.color}"></span>${item.label}</span>
      <strong>${item.value}%</strong>
    </li>
  `).join('');
}

function renderRiskBreakdown() {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  urlScanResults.forEach((scan) => {
    const category = scan.malicious === true ? 'Critical' : scan.malicious === false ? 'Low' : 'Medium';
    counts[category] += 1;
  });

  const total = urlScanResults.length;
  threatBreakdown = threatBreakdown.map((item) => ({
    ...item,
    value: total ? Math.round((counts[item.label] / total) * 100) : 0
  }));
  renderLegend();

  if (!total) {
    donutScore.textContent = '0%';
    donutLabel.textContent = 'No scans';
    donutChart.style.background = 'conic-gradient(rgba(153, 172, 190, 0.22) 0 100%)';
    return;
  }

  const leadingCategory = threatBreakdown.reduce((leading, item) => item.value > leading.value ? item : leading);
  donutScore.textContent = `${leadingCategory.value}%`;
  donutLabel.textContent = leadingCategory.label;
  let start = 0;
  const stops = threatBreakdown.map((item) => {
    const end = start + item.value;
    const stop = `${item.color} ${start}% ${end}%`;
    start = end;
    return stop;
  });
  donutChart.style.background = `conic-gradient(${stops.join(', ')})`;
}

function renderRecommendations() {
  const latestScan = urlScanResults[0];
  if (!latestScan) {
    recommendations.innerHTML = '<p class="empty-recommendations">Submit a URL scan to generate defense guidance.</p>';
    return;
  }

  const guidance = latestScan.malicious === true
    ? [
      ['danger', 'Block the flagged domain', `Add ${latestScan.domain} to DNS, firewall, and secure web gateway blocklists.`],
      ['danger', 'Investigate exposed devices', 'Quarantine affected endpoints, review browser activity, and rotate credentials entered on the site.'],
      ['warning', 'Increase identity protection', 'Require MFA and review sign-in logs for accounts that may have interacted with this URL.']
    ]
    : latestScan.malicious === false
      ? [
        ['ok', 'Continue link monitoring', `Keep ${latestScan.domain} under observation and rescan if its redirects or content change.`],
        ['ok', 'Keep web protections enabled', 'Maintain DNS filtering, HTTPS inspection, and safe-link checks for users.'],
        ['warning', 'Review before sharing', 'Confirm the destination and business purpose before distributing the URL internally.']
      ]
      : [
        ['warning', 'Do not open the URL yet', `urlscan.io did not complete a scan for ${latestScan.domain}; verify the owner and destination independently.`],
        ['warning', 'Check for sensitive data', 'Remove credentials, tokens, email addresses, or private query parameters before resubmitting.'],
        ['ok', 'Review urlscan policy details', 'Confirm the URL is publicly reachable and compliant with urlscan.io submission requirements.']
      ];

  recommendations.innerHTML = guidance.map(([tone, title, description]) => `
    <div class="rec-item ${tone}">
      <span class="rec-bullet"></span>
      <div>
        <strong>${escapeHtml(title)}</strong>
        <p>${escapeHtml(description)}</p>
      </div>
    </div>
  `).join('');
}

function renderThreatTable() {
  if (!urlScanResults.length) {
    threatTableBody.innerHTML = '<tr><td colspan="4" class="empty-table-state">Submit a URL to populate detected attack events.</td></tr>';
    return;
  }

  threatTableBody.innerHTML = urlScanResults.map((scan) => {
    const severity = scan.malicious === true ? 'Critical' : scan.malicious === false ? 'Low' : 'Medium';
    const status = scan.malicious === true ? 'Detected' : scan.malicious === false ? 'Clear' : 'Scan prevented';
    const statusClass = status.toLowerCase().replace(/\s+/g, '');
    return `
      <tr>
        <td>${escapeHtml(scan.url)}</td>
        <td>${escapeHtml(scan.domain || 'Pending')}</td>
        <td><span class="severity-pill ${severity.toLowerCase()}">${severity}</span></td>
        <td><span class="status-pill ${statusClass}">${status}</span></td>
      </tr>
    `;
  }).join('');
}

function renderReport() {
  reportThreatCount.textContent = threats.length;
  reportList.innerHTML = threats.map((item) => `
    <article class="report-item">
      <div class="report-item-header">
        <div>
          <strong>${item.name}</strong>
          <span>${item.source}</span>
        </div>
        <span class="severity-pill ${item.severity.toLowerCase()}">${item.severity}</span>
      </div>
      <div class="report-prevention">
        <span class="prevention-icon">+</span>
        <p><strong>Prevention:</strong> ${preventionMethods[item.name]}</p>
      </div>
    </article>
  `).join('');
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  })[character]);
}

function getSubmissionGuidance(error) {
  const message = error.message || 'Unknown error';
  if (/scan prevented/i.test(message)) {
    return 'urlscan.io rejected this target before scanning. Try a publicly reachable http/https URL and check urlscan.io policy restrictions.';
  }
  if (error.status === 401 || error.status === 403) {
    return 'urlscan.io rejected the API key or its permissions. Check that the key is active and allowed to submit scans.';
  }
  if (error.status === 429) {
    return 'urlscan.io rate limit reached. Wait before submitting another scan.';
  }
  if (error.status >= 500 || /reach urlscan|network|fetch/i.test(message)) {
    return 'The local proxy could not reach urlscan.io. Confirm the server is running and that the network allows outbound HTTPS.';
  }
  return 'Check the URL, API key, and urlscan.io permissions.';
}

function addPreventedScanResult(url) {
  const localResult = {
    url,
    uuid: 'No scan created',
    summary: 'urlscan.io prevented submission; local review required',
    domain: new URL(url).hostname,
    ip: 'Not checked',
    statusCode: 'Not checked',
    technologies: 'Not checked',
    prevention: 'Do not open the link until its owner, destination, and purpose are verified independently.',
    remediation: 'Confirm the URL is public and policy-compliant, remove credentials or private data, then resubmit after reviewing urlscan.io restrictions.'
  };
  urlScanResults.unshift(localResult);
  renderUrlScanResults();
  renderRiskBreakdown();
  renderReport();
}

function renderUrlScanResults() {
  const reportContent = urlScanResults.length === 0
    ? '<p class="empty-scan-results">URL scan findings will appear here after submission.</p>'
    : `
      <div class="url-scan-results-header">
        <p class="eyebrow muted">URL findings and response</p>
        <span>${urlScanResults.length} analyzed</span>
      </div>
      <div class="url-scan-report-list">
        ${urlScanResults.map((scan) => `
          <article class="url-scan-report-item ${scan.malicious ? 'scan-threat' : ''}">
            <div class="url-scan-report-heading">
              <strong>${escapeHtml(scan.url)}</strong>
              <span>${escapeHtml(scan.summary || 'Waiting for urlscan.io analysis...')}</span>
            </div>
            <div class="url-scan-facts">
              <span>Domain: ${escapeHtml(scan.domain || 'Pending')}</span>
              <span>IP: ${escapeHtml(scan.ip || 'Pending')}</span>
              <span>HTTP: ${escapeHtml(scan.statusCode || 'Pending')}</span>
              <span>Technology: ${escapeHtml(scan.technologies || 'Pending')}</span>
            </div>
            <div class="scan-guidance">
              <p><strong>Precaution:</strong> ${escapeHtml(scan.prevention || 'Wait for the urlscan.io result before opening the link.')}</p>
              <p><strong>Remediation:</strong> ${escapeHtml(scan.remediation || 'Review the completed scan and update controls based on its findings.')}</p>
            </div>
          </article>
        `).join('')}
      </div>
    `;

  analyticsUrlScanResults.innerHTML = urlScanResults.length === 0
    ? '<p class="empty-scan-results">URL scan summaries will appear here after submission.</p>'
    : `
      <div class="url-scan-results-header">
        <p class="eyebrow muted">URL scan summary</p>
        <span>${urlScanResults.length} analyzed</span>
      </div>
      <div class="url-summary-chart">
        ${urlScanResults.map((scan) => {
          const intensity = scan.malicious === true ? 100 : scan.malicious === false ? 10 : 55;
          const verdict = scan.malicious === true ? 'Threat indicators' : scan.malicious === false ? 'No malicious verdict' : 'Scan prevented';
          return `
            <div class="url-summary-row">
              <div class="url-summary-label">
                <strong>${escapeHtml(scan.domain || new URL(scan.url).hostname)}</strong>
                <span>${escapeHtml(verdict)} · HTTP ${escapeHtml(scan.statusCode || 'N/A')}</span>
              </div>
              <div class="url-summary-meter ${scan.malicious === true ? 'meter-danger' : scan.malicious === false ? 'meter-safe' : 'meter-warning'}">
                <span style="width:${intensity}%"></span>
              </div>
              <strong class="url-summary-value">${intensity}</strong>
            </div>
            <div class="url-result-graph" aria-label="URL scan metrics">
              ${[
                ['Threat', intensity, scan.malicious === true ? 'metric-danger' : scan.malicious === false ? 'metric-safe' : 'metric-warning'],
                ['HTTP', scan.statusCode >= 200 && scan.statusCode < 400 ? 100 : 35, 'metric-primary'],
                ['Requests', Math.min((scan.requestCount || 0) * 2, 100), 'metric-primary'],
                ['Domains', Math.min((scan.domainCount || 0) * 10, 100), 'metric-secondary'],
                ['IPs', Math.min((scan.ipCount || 0) * 10, 100), 'metric-secondary']
              ].map(([label, value, className]) => `
                <div class="url-result-bar">
                  <span>${label}</span>
                  <div class="url-result-track ${className}"><i style="height:${value}%"></i></div>
                </div>
              `).join('')}
            </div>
          `;
        }).join('')}
      </div>
    `;
  reportUrlScanResults.innerHTML = reportContent;
  renderThreatTable();
  renderRecommendations();
}

function summarizeUrlScan(scanData) {
  const page = scanData.page || {};
  const overall = scanData.verdicts?.overall || {};
  const statusCode = page.status || page.statusCode || 'Unknown';
  const technologies = (scanData.technologies || [])
    .map((technology) => technology.app || technology.name)
    .filter(Boolean)
    .slice(0, 3);
  const malicious = overall.malicious === true;
  const summary = malicious
    ? 'urlscan.io flagged malicious indicators'
    : `No malicious verdict (${statusCode} response)`;

  return {
    malicious,
    summary,
    domain: page.domain || page.url || 'Unknown domain',
    ip: page.ip || 'Not reported',
    statusCode,
    requestCount: scanData.stats?.requests || 0,
    domainCount: scanData.stats?.uniqDomains || 0,
    ipCount: scanData.stats?.uniqIPs || 0,
    technologies: technologies.length ? technologies.join(', ') : 'Not reported',
    prevention: malicious
      ? 'Block the domain and related indicators, quarantine affected messages or endpoints, and require security review before access.'
      : 'Keep link protection, DNS filtering, HTTPS checks, and user reporting enabled before allowing access.',
    remediation: malicious
      ? 'Investigate affected users and devices, rotate exposed credentials, and add the indicators to firewall, DNS, and endpoint deny lists.'
      : 'Record the scan, monitor the domain for changes, and rescan if the URL redirects or its content changes.'
  };
}

async function loadUrlScanResult(scan, apiKey) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await fetch('/api/urlscan/result', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uuid: scan.uuid, apiKey })
      });

      if (response.ok) {
        Object.assign(scan, summarizeUrlScan(await response.json()));
        renderUrlScanResults();
        renderRiskBreakdown();
        renderReport();
        return;
      }
    } catch (error) {
      // The scan can still be processing; keep the submitted result visible.
    }

    await new Promise((resolve) => window.setTimeout(resolve, 3000));
  }

  scan.summary = 'Scan submitted; urlscan.io is still processing the result';
  renderUrlScanResults();
}

function setAuthMode(mode) {
  authMode = mode;
  const isRegistering = mode === 'register';

  document.querySelectorAll('.register-only').forEach((field) => {
    field.hidden = !isRegistering;
    field.querySelector('input').required = isRegistering;
  });
  document.querySelectorAll('.login-only').forEach((field) => {
    field.hidden = isRegistering;
  });
  loginTab.classList.toggle('active', !isRegistering);
  registerTab.classList.toggle('active', isRegistering);
  loginTab.setAttribute('aria-selected', String(!isRegistering));
  registerTab.setAttribute('aria-selected', String(isRegistering));
  authTitle.textContent = isRegistering ? 'Create your account' : 'Welcome back';
  authDescription.textContent = isRegistering
    ? 'Set up your secure workspace profile to begin monitoring threats.'
    : 'Sign in to continue to your security command center.';
  authSubmit.textContent = isRegistering ? 'Create account' : 'Log in securely';
  formMessage.textContent = '';
  formMessage.className = 'form-message';
}

function openAuth(mode = 'login') {
  setAuthMode(mode);
  authBackdrop.hidden = false;
  document.body.classList.add('modal-open');
  window.requestAnimationFrame(() => document.getElementById('email').focus());
}

function closeAuth() {
  authBackdrop.hidden = true;
  document.body.classList.remove('modal-open');
  authForm.reset();
  setAuthMode('login');
}

loginButton.addEventListener('click', () => openAuth());
closeAuthButton.addEventListener('click', closeAuth);
loginTab.addEventListener('click', () => setAuthMode('login'));
registerTab.addEventListener('click', () => setAuthMode('register'));
authBackdrop.addEventListener('click', (event) => {
  if (event.target === authBackdrop) closeAuth();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !authBackdrop.hidden) closeAuth();
});
authForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const formData = new FormData(authForm);
  const password = formData.get('password');

  if (authMode === 'register' && password !== formData.get('confirmPassword')) {
    formMessage.textContent = 'Passwords do not match.';
    formMessage.className = 'form-message error';
    return;
  }

  formMessage.textContent = authMode === 'register'
    ? 'Account created. Your secure workspace is ready.'
    : 'Signed in successfully. Welcome to CyberMirror.';
  formMessage.className = 'form-message success';
  authForm.reset();
});

function openReport() {
  renderReport();
  reportBackdrop.hidden = false;
  document.body.classList.add('modal-open');
}

function closeReport() {
  reportBackdrop.hidden = true;
  document.body.classList.remove('modal-open');
}

reportsNavButton.addEventListener('click', openReport);
closeReportButton.addEventListener('click', closeReport);
reportBackdrop.addEventListener('click', (event) => {
  if (event.target === reportBackdrop) closeReport();
});

threatAnalyticsNavButton.addEventListener('click', () => {
  threatAnalyticsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.remove('active'));
  threatAnalyticsNavButton.classList.add('active');
});

urlScannerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const rawUrl = urlInput.value.trim();
  const apiKey = urlscanApiKey.value.trim();
  let parsedUrl;

  try {
    parsedUrl = new URL(rawUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('Unsupported protocol');
  } catch (error) {
    scannerStatus.textContent = 'Invalid URL';
    scannerStatus.className = 'scanner-status danger-status';
    scanResult.className = 'scan-result result-danger';
    scanResult.innerHTML = '<span class="scan-result-icon">!</span><div><strong>Enter a valid HTTP or HTTPS URL</strong><p>Include the full address, such as https://example.com.</p></div>';
    return;
  }

  if (!apiKey) {
    scannerStatus.textContent = 'API key required';
    scannerStatus.className = 'scanner-status danger-status';
    scanResult.className = 'scan-result result-danger';
    scanResult.innerHTML = '<span class="scan-result-icon">!</span><div><strong>Enter your urlscan.io API key</strong><p>The key is sent only in the API-Key header and is not stored.</p></div>';
    return;
  }

  scannerStatus.textContent = 'Submitting scan';
  scannerStatus.className = 'scanner-status';
  scanResult.className = 'scan-result';
  scanResult.innerHTML = '<span class="scan-result-icon">...</span><div><strong>Sending URL to urlscan.io</strong><p>Waiting for the scan submission response.</p></div>';

  try {
    if (window.location.protocol === 'file:') {
      throw new Error('Open CyberMirror through http://localhost:3000 after starting server.py');
    }

    const response = await fetch('/api/urlscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: parsedUrl.href, apiKey })
    });
    const result = await response.json();

    if (!response.ok) {
      const apiError = new Error(result.message || `urlscan.io returned ${response.status}`);
      apiError.status = result.status || response.status;
      apiError.description = result.description;
      throw apiError;
    }

    scannerStatus.textContent = 'Scan submitted';
    scannerStatus.className = 'scanner-status safe-status';
    scanResult.className = 'scan-result result-safe';
    scanResult.innerHTML = `<span class="scan-result-icon">&#10003;</span><div><strong>URL submitted successfully</strong><p>Scan ID: ${escapeHtml(result.uuid || 'Pending')}</p></div>`;
    const submittedScan = { url: parsedUrl.href, uuid: result.uuid, resultUrl: result.result };
    urlScanResults.unshift(submittedScan);
    renderUrlScanResults();
    renderRiskBreakdown();
    loadUrlScanResult(submittedScan, apiKey);
  } catch (error) {
    const errorDetails = error.description ? ` ${error.description}` : '';
    if (/scan prevented/i.test(error.message)) {
      scannerStatus.textContent = 'Scan blocked by urlscan.io';
      scannerStatus.className = 'scanner-status warning-status';
      scanResult.className = 'scan-result result-warning';
      scanResult.innerHTML = '<span class="scan-result-icon">!</span><div><strong>urlscan.io prevented this scan</strong><p>No scan was created. A local safety result was added to Threat Analytics and Reports.</p></div>';
      addPreventedScanResult(parsedUrl.href);
      return;
    }

    scannerStatus.textContent = 'Submission failed';
    scannerStatus.className = 'scanner-status danger-status';
    scanResult.className = 'scan-result result-danger';
    scanResult.innerHTML = `<span class="scan-result-icon">!</span><div><strong>Could not submit URL</strong><p>${escapeHtml(error.message)}.${escapeHtml(errorDetails)} ${escapeHtml(getSubmissionGuidance(error))}</p></div>`;
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !reportBackdrop.hidden) closeReport();
});

renderLegend();
renderRiskBreakdown();
renderThreatTable();
renderReport();
renderUrlScanResults();
