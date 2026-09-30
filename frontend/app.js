/**
 * CipherIntel // Threat Intelligence & File Analysis
 * High-Fidelity SOC Analyst Frontend Controller
 * Features:
 * 1. Interactive HTML5 Canvas Cyber Constellation / Threat Mesh
 * 2. Tactical 4-Pillar IOC Switcher & Quick Test Presets
 * 3. Live Radar / Circular Scanning Motion
 * 4. Dynamic Risk Gauge & Multi-Source Results Dossier
 * 5. Recent Investigations HUD (Rolling 2-Item Flight Log)
 * 6. Top-Level Module Toggle: [IOC Telemetry] vs [Binary & Artifact Analysis]
 * 7. Multi-Factor Contextual Risk Breakdown Card (35%, 30%, 25%, 10%)
 * 8. MITRE ATT&CK Matrix Grid with Interactive Threat Cards
 * 9. Safe In-Memory Static PE Analyzer & Shannon Entropy Visualizer
 * 10. Flagged IAT APIs with Associated MITRE Techniques
 * 11. Extracted Network IOCs with One-Click "Pivot to Lookup"
 * 12. Custom YARA Studio with Real-Time Rule Compilation & Evaluation
 */

// Determine API Base URL
const API_BASE_URL = (window.location.origin && window.location.origin.startsWith('http') && !window.location.origin.includes('5500'))
  ? window.location.origin
  : 'http://127.0.0.1:8000';

const TOKEN_KEY = 'cipherintel_jwt_token';
const LEGACY_TOKEN_KEY = 'sentinelscope_jwt_token';

// Global App State
const state = {
  token: localStorage.getItem(TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY) || null,
  currentUser: null,
  authMode: 'login', // 'login' or 'register'
  activeModule: 'ioc', // 'ioc' or 'artifact'
  activePillar: 'ip', // 'ip', 'domain', 'url', 'hash'
  detectedType: null,
  lastAnalysis: null,
  currentArtifactFile: null,
  lastArtifactReport: null,
};

// Active Analysis Cache for Risk Drilldown Modal
let currentAnalysisData = null;

// DOM Elements
const el = {
  // Views & Shell
  authView: document.getElementById('auth-view'),
  dashboardView: document.getElementById('dashboard-view'),
  toastContainer: document.getElementById('toast-container'),

  // Module Navigation Tabs
  navTabIoc: document.getElementById('nav-tab-ioc'),
  navTabArtifact: document.getElementById('nav-tab-artifact'),
  moduleIocContainer: document.getElementById('module-ioc-container'),
  moduleArtifactContainer: document.getElementById('module-artifact-container'),

  // Auth Elements
  tabLogin: document.getElementById('tab-login'),
  tabRegister: document.getElementById('tab-register'),
  authForm: document.getElementById('auth-form'),
  authUsername: document.getElementById('auth-username'),
  authPassword: document.getElementById('auth-password'),
  authSubmitBtn: document.getElementById('auth-submit-btn'),
  authBtnText: document.getElementById('auth-btn-text'),
  authSpinner: document.getElementById('auth-spinner'),
  authAlert: document.getElementById('auth-alert'),

  // Header Elements
  headerUsername: document.getElementById('header-username'),
  logoutBtn: document.getElementById('logout-btn'),
  utcClock: document.getElementById('utc-clock'),

  // 4-Pillar Switcher & Input Console
  pillarTabs: document.querySelectorAll('.pillar-tab'),
  analyzeForm: document.getElementById('analyze-form'),
  inputContainerWrapper: document.getElementById('input-container-wrapper'),
  iocInput: document.getElementById('ioc-input'),
  inputModeIcon: document.getElementById('input-mode-icon'),
  detectedTypeBadge: document.getElementById('detected-type-badge'),
  autoSwitchHintBtn: document.getElementById('auto-switch-hint-btn'),
  analyzeSubmitBtn: document.getElementById('analyze-submit-btn'),
  analyzeBtnText: document.getElementById('analyze-btn-text'),
  analyzeBtnIcon: document.getElementById('analyze-btn-icon'),
  analyzeSpinner: document.getElementById('analyze-spinner'),
  quickChips: document.querySelectorAll('.quick-chip'),

  // Recent Investigations HUD
  historyContainer: document.getElementById('history-container'),
  refreshHistoryBtn: document.getElementById('refresh-history-btn'),

  // Scanning Loader (IOC)
  scanningLoader: document.getElementById('scanning-loader'),

  // Results Section (IOC)
  resultsSection: document.getElementById('results-section'),
  resultIocTypePill: document.getElementById('result-ioc-type-pill'),
  resultDefangedIoc: document.getElementById('result-defanged-ioc'),
  resultOriginalIoc: document.getElementById('result-original-ioc'),
  resultClassificationLabel: document.getElementById('result-classification-label'),
  copyDefangedBtn: document.getElementById('copy-defanged-btn'),
  copyBtnText: document.getElementById('copy-btn-text'),

  // Threat Gauge
  gaugeCircleProgress: document.getElementById('gauge-circle-progress'),
  resultThreatScore: document.getElementById('result-threat-score'),
  resultSeverityBadge: document.getElementById('result-severity-badge'),
  resultScoreBreakdown: document.getElementById('result-score-breakdown'),

  // Task 3.2: Multi-Factor Breakdown Card (Refactored 4-Card Architecture)
  resultMultifactorCard: document.getElementById('result-multifactor-card'),
  multifactorVerdictBadge: document.getElementById('multifactor-verdict-badge'),
  meterEngineBar: document.getElementById('meter-engine-bar'),
  meterEngineVal: document.getElementById('meter-engine-val'),
  meterEngineDetail: document.getElementById('meter-engine-detail'),
  meterConsensusBadge: document.getElementById('meter-consensus-badge'),
  meterThreatBar: document.getElementById('meter-threat-bar'),
  meterThreatVal: document.getElementById('meter-threat-val'),
  meterThreatDetail: document.getElementById('meter-threat-detail'),
  meterTaxonomyBadge: document.getElementById('meter-taxonomy-badge'),
  meterConfidenceBar: document.getElementById('meter-confidence-bar'),
  meterConfidenceVal: document.getElementById('meter-confidence-val'),
  meterConfidenceDetail: document.getElementById('meter-confidence-detail'),
  meterInfraBadge: document.getElementById('meter-infra-badge'),
  meterHeuristicsBar: document.getElementById('meter-heuristics-bar'),
  meterHeuristicsVal: document.getElementById('meter-heuristics-val'),
  meterHeuristicsDetail: document.getElementById('meter-heuristics-detail'),
  meterHeuristicsBadge: document.getElementById('meter-heuristics-badge'),

  // Risk Score Factor Interactive Drilldown Cards & Modal
  cardFactor1: document.getElementById('card-factor-1'),
  cardFactor2: document.getElementById('card-factor-2'),
  cardFactor3: document.getElementById('card-factor-3'),
  cardFactor4: document.getElementById('card-factor-4'),
  riskDrilldownModal: document.getElementById('risk-drilldown-modal'),
  drilldownFactorNum: document.getElementById('drilldown-factor-num'),
  drilldownBadge: document.getElementById('drilldown-badge'),
  drilldownTitle: document.getElementById('drilldown-title'),
  drilldownSubtitle: document.getElementById('drilldown-subtitle'),
  drilldownCloseBtn: document.getElementById('drilldown-close-btn'),
  drilldownCloseBtnBottom: document.getElementById('drilldown-close-btn-bottom'),
  drilldownContent: document.getElementById('drilldown-content'),
  drilldownFactorPts: document.getElementById('drilldown-factor-pts'),

  // Task 3.2: MITRE ATT&CK Matrix Grid
  mitreMatrixGrid: document.getElementById('mitre-matrix-grid'),
  mitreCountBadge: document.getElementById('mitre-count-badge'),

  // VirusTotal Dossier
  vtStatusPill: document.getElementById('vt-status-pill'),
  vtDetectionsText: document.getElementById('vt-detections-text'),
  vtBarMalicious: document.getElementById('vt-bar-malicious'),
  vtBarSuspicious: document.getElementById('vt-bar-suspicious'),
  vtBarHarmless: document.getElementById('vt-bar-harmless'),
  vtBarUndetected: document.getElementById('vt-bar-undetected'),
  vtReputation: document.getElementById('vt-reputation'),
  vtOwner: document.getElementById('vt-owner'),
  vtCountry: document.getElementById('vt-country'),

  // Secondary Vendor Dossier
  vendor2Icon: document.getElementById('vendor2-icon'),
  vendor2Title: document.getElementById('vendor2-title'),
  vendor2Subtitle: document.getElementById('vendor2-subtitle'),
  vendor2StatusPill: document.getElementById('vendor2-status-pill'),
  vendor2Content: document.getElementById('vendor2-content'),

  // Playbook Checklist
  checklistItems: document.getElementById('checklist-items'),
  checklistProgressText: document.getElementById('checklist-progress-text'),
  checklistPercent: document.getElementById('checklist-percent'),
  downloadReportBtn: document.getElementById('download-report-btn'),

  // =========================================================================
  // Task 3.3: Binary & Static Artifact Analysis Elements
  // =========================================================================
  artifactDropzone: document.getElementById('artifact-dropzone'),
  artifactFileInput: document.getElementById('artifact-file-input'),
  artifactStagedBar: document.getElementById('artifact-staged-bar'),
  artifactStagedFilename: document.getElementById('artifact-staged-filename'),
  artifactStagedSize: document.getElementById('artifact-staged-size'),
  artifactStagedType: document.getElementById('artifact-staged-type'),
  artifactAnalyzeBtn: document.getElementById('artifact-analyze-btn'),
  artifactAnalyzeIcon: document.getElementById('artifact-analyze-icon'),
  artifactAnalyzeSpinner: document.getElementById('artifact-analyze-spinner'),
  artifactAnalyzeBtnText: document.getElementById('artifact-analyze-btn-text'),
  artifactScanningLoader: document.getElementById('artifact-scanning-loader'),
  artifactResultsSection: document.getElementById('artifact-results-section'),

  // Artifact Executive Card
  artPeBadge: document.getElementById('art-pe-badge'),
  artPackingBadge: document.getElementById('art-packing-badge'),
  artFilenameTitle: document.getElementById('art-filename-title'),
  artStaticScore: document.getElementById('art-static-score'),
  artStaticVerdictBadge: document.getElementById('art-static-verdict-badge'),
  artSha256: document.getElementById('art-sha256'),
  artMachine: document.getElementById('art-machine'),
  artTimestamp: document.getElementById('art-timestamp'),
  artSubsystem: document.getElementById('art-subsystem'),
  artSectionsCount: document.getElementById('art-sections-count'),
  artPackingAlert: document.getElementById('art-packing-alert'),
  artPackingList: document.getElementById('art-packing-list'),

  // Entropy Visualizer
  artOverallEntropy: document.getElementById('art-overall-entropy'),
  artSectionsContainer: document.getElementById('art-sections-container'),

  // IAT & Suspicious APIs
  artFlaggedApisCount: document.getElementById('art-flagged-apis-count'),
  artFlaggedApisContainer: document.getElementById('art-flagged-apis-container'),
  artDllsList: document.getElementById('art-dlls-list'),

  // Extracted IOCs
  artExtractedIocsCount: document.getElementById('art-extracted-iocs-count'),
  artExtractedIocsContainer: document.getElementById('art-extracted-iocs-container'),

  // Custom YARA Studio
  yaraPresetUpx: document.getElementById('yara-preset-upx'),
  yaraPresetInjection: document.getElementById('yara-preset-injection'),
  yaraPresetPowershell: document.getElementById('yara-preset-powershell'),
  yaraRuleEditor: document.getElementById('yara-rule-editor'),
  yaraExecuteBtn: document.getElementById('yara-execute-btn'),
  yaraBtnIcon: document.getElementById('yara-btn-icon'),
  yaraSpinner: document.getElementById('yara-spinner'),
  yaraBtnText: document.getElementById('yara-btn-text'),
  yaraResultsContainer: document.getElementById('yara-results-container'),
};

// 4-Pillar Configuration
const PILLAR_CONFIG = {
  ip: {
    placeholder: 'e.g. 185.220.101.5 (Tor Exit Node) or 1.1.1.1 (Public IPv4)',
    iconSvg: `<svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>`,
  },
  domain: {
    placeholder: 'e.g. secure-login-verify-account.com or example.com (FQDN)',
    iconSvg: `<svg class="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>`,
  },
  url: {
    placeholder: 'e.g. http://malware-dist.xyz/payload.exe or https://phish-bank.com/auth',
    iconSvg: `<svg class="w-4 h-4 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16zm-1-13l4 4-4 4v-8z"/></svg>`,
  },
  hash: {
    placeholder: 'e.g. 44d88612fea8a8f36de82e1278abb02f (MD5) or 275a021b... (SHA256)',
    iconSvg: `<svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`,
  },
};

// ============================================================================
// 1. INTERACTIVE HTML5 CANVAS CYBER CONSTELLATION / THREAT MESH
// ============================================================================
function initCyberMeshCanvas() {
  const canvas = document.getElementById('cyber-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const mouse = { x: null, y: null, radius: 140 };
  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });
  window.addEventListener('mouseout', () => {
    mouse.x = null;
    mouse.y = null;
  });

  const nodeCount = Math.min(65, Math.max(35, Math.floor((width * height) / 22000)));
  const nodes = [];
  const colorPalette = ['#6366f1', '#818cf8', '#38bdf8', '#a855f7'];

  class Node {
    constructor() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.6;
      this.vy = (Math.random() - 0.5) * 0.6;
      this.radius = Math.random() * 1.8 + 1.1;
      this.color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
      this.alpha = Math.random() * 0.25 + 0.35;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0 || this.x > width) this.vx = -this.vx;
      if (this.y < 0 || this.y > height) this.vy = -this.vy;

      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          this.x -= (dx / dist) * force * 1.5;
          this.y -= (dy / dist) * force * 1.5;
        }
      }
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.shadowBlur = 8;
      ctx.shadowColor = this.color;
      ctx.globalAlpha = this.alpha;
      ctx.fill();
    }
  }

  for (let i = 0; i < nodeCount; i++) {
    nodes.push(new Node());
  }

  function renderMesh() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < nodes.length; i++) {
      nodes[i].update();
      nodes[i].draw();

      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 125) {
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = '#6366f1';
          ctx.globalAlpha = (1 - dist / 125) * 0.18;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }

      if (mouse.x !== null && mouse.y !== null) {
        const dx = nodes[i].x - mouse.x;
        const dy = nodes[i].y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < mouse.radius) {
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = '#818cf8';
          ctx.globalAlpha = (1 - dist / mouse.radius) * 0.3;
          ctx.lineWidth = 1.0;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(renderMesh);
  }

  renderMesh();
}

// ============================================================================
// TOAST NOTIFICATION ENGINE
// ============================================================================
function showToast(title, message, type = 'info', duration = 4000) {
  const toast = document.createElement('div');
  toast.className = 'pointer-events-auto p-3.5 rounded-2xl border backdrop-blur-xl transition-all transform duration-300 translate-y-2 opacity-0 flex items-start gap-3 text-xs font-mono';

  let borderClass = 'border-indigo-500/30 bg-[#0D111A]/95 text-indigo-300 shadow-xl shadow-indigo-950/40';
  let iconSvg = `<svg class="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;

  if (type === 'error') {
    borderClass = 'border-rose-500/40 bg-[#0D111A]/95 text-rose-300 shadow-xl shadow-rose-950/40';
    iconSvg = `<svg class="w-4 h-4 text-rose-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
  } else if (type === 'success') {
    borderClass = 'border-emerald-500/40 bg-[#0D111A]/95 text-emerald-300 shadow-xl shadow-emerald-950/40';
    iconSvg = `<svg class="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
  } else if (type === 'warning') {
    borderClass = 'border-amber-500/40 bg-[#0D111A]/95 text-amber-300 shadow-xl shadow-amber-950/40';
    iconSvg = `<svg class="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  }

  toast.classList.add(...borderClass.split(' '));
  toast.innerHTML = `
    ${iconSvg}
    <div class="flex-1">
      <div class="font-bold tracking-wider uppercase text-[11px] mb-0.5">${title}</div>
      <div class="text-slate-300 leading-relaxed text-[11px]">${message}</div>
    </div>
  `;

  el.toastContainer.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', '-translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// Live UTC Chronometer
function updateUtcClock() {
  const now = new Date();
  const utcStr = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  if (el.utcClock) el.utcClock.textContent = utcStr;
}
setInterval(updateUtcClock, 1000);
updateUtcClock();

// ============================================================================
// API CLIENT (PASSES BEARER TOKEN & INTERCEPTS 401)
// ============================================================================
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = options.headers || {};

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  options.headers = headers;

  try {
    const response = await fetch(url, options);

    if (response.status === 401) {
      handleUnauthorized();
      throw new Error('Session has expired. Re-authentication required.');
    }

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const errorMsg = data && data.detail ? data.detail : `Request failed with HTTP ${response.status}`;
      throw new Error(errorMsg);
    }

    return data;
  } catch (error) {
    throw error;
  }
}

function handleUnauthorized() {
  localStorage.removeItem(TOKEN_KEY);
  state.token = null;
  state.currentUser = null;
  showAuthView();
  showToast('SESSION TERMINATED', 'Your JWT access token has expired or is invalid.', 'warning');
}

// ============================================================================
// AUTH VIEW CONTROLLERS
// ============================================================================
function showAuthView() {
  el.authView.classList.remove('hidden');
  el.dashboardView.classList.add('hidden');
  el.authUsername.value = '';
  el.authPassword.value = '';
}

function showDashboardView(username) {
  state.currentUser = username;
  el.headerUsername.textContent = username;
  el.authView.classList.add('hidden');
  el.dashboardView.classList.remove('hidden');

  // Activate default module and default pillar (IP)
  switchModule('ioc');
  switchPillar('ip');

  // Sync flight log
  loadSearchHistory();
}

function setAuthMode(mode) {
  state.authMode = mode;
  el.authAlert.classList.add('hidden');

  if (mode === 'login') {
    el.tabLogin.className = 'flex-1 py-2 rounded-lg font-semibold text-xs tracking-wide transition-all bg-indigo-600 text-white shadow-sm shadow-indigo-500/25 border border-indigo-400/30';
    el.tabRegister.className = 'flex-1 py-2 rounded-lg font-semibold text-xs tracking-wide transition-all text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent';
    el.authBtnText.textContent = 'Sign In';
  } else {
    el.tabRegister.className = 'flex-1 py-2 rounded-lg font-semibold text-xs tracking-wide transition-all bg-indigo-600 text-white shadow-sm shadow-indigo-500/25 border border-indigo-400/30';
    el.tabLogin.className = 'flex-1 py-2 rounded-lg font-semibold text-xs tracking-wide transition-all text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent';
    el.authBtnText.textContent = 'Sign Up';
  }
}

el.tabLogin.addEventListener('click', () => setAuthMode('login'));
el.tabRegister.addEventListener('click', () => setAuthMode('register'));

el.authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  el.authAlert.classList.add('hidden');

  const username = el.authUsername.value.trim();
  const password = el.authPassword.value;

  if (!username || !password) return;

  el.authSubmitBtn.disabled = true;
  el.authSpinner.classList.remove('hidden');
  el.authBtnText.textContent = state.authMode === 'login' ? 'Signing in...' : 'Signing up...';

  try {
    if (state.authMode === 'register') {
      await apiRequest('/api/auth/register', {
        method: 'POST',
        body: { username, password },
      });
      showToast('OPERATOR REGISTERED', `Credentials created for [${username}].`, 'success');
    }

    const loginData = await apiRequest('/api/auth/login', {
      method: 'POST',
      body: { username, password },
    });

    localStorage.setItem(TOKEN_KEY, loginData.access_token);
    state.token = loginData.access_token;
    showDashboardView(username);
    showToast('SESSION ESTABLISHED', `Welcome, Analyst [${username}]. Command interface ready.`, 'success');
  } catch (error) {
    el.authAlert.classList.remove('hidden');
    el.authAlert.className = 'mb-4 p-3 rounded-xl text-xs font-mono border bg-rose-500/10 text-rose-400 border-rose-500/30';
    el.authAlert.textContent = error.message;
  } finally {
    el.authSubmitBtn.disabled = false;
    el.authSpinner.classList.add('hidden');
    el.authBtnText.textContent = state.authMode === 'login' ? 'Sign In' : 'Sign Up';
  }
});

el.logoutBtn.addEventListener('click', () => {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
  state.token = null;
  state.currentUser = null;
  state.lastAnalysis = null;
  currentAnalysisData = null;
  state.currentArtifactFile = null;
  state.lastArtifactReport = null;
  closeRiskDrilldownModal();
  el.resultsSection.classList.add('hidden');
  showAuthView();
  showToast('DISCONNECTED', 'Operator session successfully terminated.', 'info');
});

async function initializeApp() {
  if (state.token) {
    try {
      const profile = await apiRequest('/api/auth/me');
      showDashboardView(profile.username);
      return;
    } catch (e) {
      handleUnauthorized();
    }
  }
  showAuthView();
}

// ============================================================================
// Task 3.1: TOP-LEVEL MODULE NAVIGATION TOGGLE
// ============================================================================
function switchModule(moduleName) {
  state.activeModule = moduleName;

  if (moduleName === 'ioc') {
    el.navTabIoc.className = 'flex-1 py-2.5 px-4 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all bg-indigo-600 text-white shadow-sm shadow-indigo-500/25 border border-indigo-400/30 tracking-wide';
    el.navTabArtifact.className = 'flex-1 py-2.5 px-4 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent tracking-wide';
    el.moduleIocContainer.classList.remove('hidden');
    el.moduleArtifactContainer.classList.add('hidden');
  } else {
    el.navTabArtifact.className = 'flex-1 py-2.5 px-4 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all bg-indigo-600 text-white shadow-sm shadow-indigo-500/25 border border-indigo-400/30 tracking-wide';
    el.navTabIoc.className = 'flex-1 py-2.5 px-4 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent tracking-wide';
    el.moduleArtifactContainer.classList.remove('hidden');
    el.moduleIocContainer.classList.add('hidden');
  }
}

el.navTabIoc.addEventListener('click', () => switchModule('ioc'));
el.navTabArtifact.addEventListener('click', () => switchModule('artifact'));

// ============================================================================
// 2. TACTICAL 4-PILLAR IOC SWITCHER & QUICK TEST CHIPS
// ============================================================================
function switchPillar(mode) {
  state.activePillar = mode;
  const config = PILLAR_CONFIG[mode];
  if (!config) return;

  el.pillarTabs.forEach((tab) => {
    const tabMode = tab.getAttribute('data-mode');
    if (tabMode === mode) {
      tab.className = 'pillar-tab flex-1 py-2 px-3 rounded-lg font-medium flex items-center justify-center gap-1.5 transition-all bg-indigo-600 text-white shadow-sm shadow-indigo-500/25 border border-indigo-400/30';
    } else {
      tab.className = 'pillar-tab flex-1 py-2 px-3 rounded-lg font-medium flex items-center justify-center gap-1.5 transition-all text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent';
    }
  });

  el.iocInput.placeholder = config.placeholder;
  el.inputModeIcon.innerHTML = config.iconSvg;

  handleIocInputDetection();
}

el.pillarTabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    const mode = tab.getAttribute('data-mode');
    switchPillar(mode);
  });
});

// Quick-Test Chips Handler
el.quickChips.forEach((chip) => {
  chip.addEventListener('click', () => {
    const type = chip.getAttribute('data-type');
    const val = chip.getAttribute('data-val');

    if (type && PILLAR_CONFIG[type]) {
      switchPillar(type);
    }

    el.iocInput.value = val;
    handleIocInputDetection();
    runAnalysis(val);
  });
});

// Real-Time Regex Detection
const REGEX = {
  hash: /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$/,
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  url: /^(?:https?|hxxps?|ftp):\/\/[^\s/$.?#].[^\s]*$/i,
  domain: /^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\[\.\]|\.))+[a-zA-Z]{2,63}$/,
  rfc1918: /^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/,
};

function classifyString(val) {
  if (!val) return null;
  const clean = val.trim();

  if (REGEX.hash.test(clean)) return 'hash';
  if (REGEX.ipv4.test(clean)) return 'ip';
  if (REGEX.url.test(clean) || (clean.includes('://') || (clean.includes('/') && !clean.startsWith('/')))) return 'url';
  if (REGEX.domain.test(clean)) return 'domain';
  return 'unknown';
}

function handleIocInputDetection() {
  const val = el.iocInput.value.trim();

  if (!val) {
    el.detectedTypeBadge.textContent = `[PILLAR: ${state.activePillar.toUpperCase()}]`;
    el.detectedTypeBadge.className = 'px-2 py-0.5 rounded text-[11px] font-mono font-bold border bg-transparent text-slate-400 border-white/[0.08]';
    el.autoSwitchHintBtn.classList.add('hidden');
    state.detectedType = null;
    return;
  }

  const detected = classifyString(val);
  state.detectedType = detected;

  // RFC1918 Guard Alert
  if (detected === 'ip' && REGEX.rfc1918.test(val.replace(/\[\.\]/g, '.'))) {
    el.detectedTypeBadge.textContent = '[RFC1918 PRIVATE IP]';
    el.detectedTypeBadge.className = 'px-2 py-0.5 rounded text-[11px] font-mono font-bold border bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse';
    el.autoSwitchHintBtn.classList.add('hidden');
    return;
  }

  if (detected === state.activePillar) {
    el.detectedTypeBadge.textContent = `[MATCH: ${detected.toUpperCase()}]`;
    el.detectedTypeBadge.className = 'px-2 py-0.5 rounded text-[11px] font-mono font-bold border bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    el.autoSwitchHintBtn.classList.add('hidden');
  } else if (detected && detected !== 'unknown') {
    el.detectedTypeBadge.textContent = `[DETECTED: ${detected.toUpperCase()}]`;
    el.detectedTypeBadge.className = 'px-2 py-0.5 rounded text-[11px] font-mono font-bold border bg-amber-500/10 text-amber-400 border-amber-500/30';
    el.autoSwitchHintBtn.textContent = `⚡ Switch to ${detected.toUpperCase()}`;
    el.autoSwitchHintBtn.classList.remove('hidden');
  } else {
    el.detectedTypeBadge.textContent = '[UNRECOGNIZED FORMAT]';
    el.detectedTypeBadge.className = 'px-2 py-0.5 rounded text-[11px] font-mono font-bold border bg-transparent text-slate-500 border-white/[0.08]';
    el.autoSwitchHintBtn.classList.add('hidden');
  }
}

el.iocInput.addEventListener('input', handleIocInputDetection);

el.autoSwitchHintBtn.addEventListener('click', () => {
  if (state.detectedType && state.detectedType !== 'unknown') {
    switchPillar(state.detectedType);
    showToast('PILLAR SWITCHED', `Active console switched to [${state.detectedType.toUpperCase()}].`, 'info');
  }
});

// ============================================================================
// 5. "RECENT INVESTIGATIONS" HUD (Strictly Last 2 Searches)
// ============================================================================
async function loadSearchHistory() {
  if (!state.token) return;

  try {
    const list = await apiRequest('/api/history');
    renderRecentInvestigations(list);
  } catch (error) {
    console.error('Failed to load history:', error);
  }
}

function renderRecentInvestigations(items) {
  el.historyContainer.innerHTML = '';

  if (!items || items.length === 0) {
    el.historyContainer.innerHTML = `
      <div class="col-span-full p-3.5 border border-dashed border-white/[0.08] rounded-xl text-center font-mono text-xs text-slate-400 bg-transparent">
        STANDBY: NO PRIOR INVESTIGATIONS IN SESSION
      </div>
    `;
    return;
  }

  items.slice(0, 2).forEach((item) => {
    const card = document.createElement('div');
    card.className = 'p-3 bg-[#0D111A]/80 hover:bg-[#131926] border border-white/[0.08] hover:border-white/[0.16] rounded-xl transition-all cursor-pointer group flex flex-col justify-between shadow-sm active:scale-[0.99] backdrop-blur-sm';
    card.title = `Click to re-interrogate ${item.ioc}`;

    let chipClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (item.severity === 'High') {
      chipClass = 'bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-neon-crimson';
    } else if (item.severity === 'Medium') {
      chipClass = 'bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-neon-amber';
    }

    const typeUpper = (item.ioc_type || 'IOC').toUpperCase();
    const timeStr = item.searched_at ? new Date(item.searched_at).toLocaleTimeString() : 'Recent';

    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-500/10 border border-indigo-500/25 text-indigo-400">
            [${typeUpper}]
          </span>
          <span class="text-xs font-mono font-semibold text-slate-200 group-hover:text-indigo-300 transition-colors truncate">
            ${item.defanged_ioc || item.ioc}
          </span>
        </div>
        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase border ${chipClass}">
          ${item.severity}
        </span>
      </div>

      <div class="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 mt-1 border-t border-white/[0.06]">
        <span>SCORE: <strong class="text-slate-300 font-bold">${item.threat_score}</strong>/100</span>
        <span class="text-indigo-400/70 group-hover:text-indigo-300 flex items-center gap-1 font-semibold">
          <span>${timeStr}</span>
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        </span>
      </div>
    `;

    card.addEventListener('click', () => {
      switchModule('ioc');
      if (item.ioc_type && PILLAR_CONFIG[item.ioc_type]) {
        switchPillar(item.ioc_type);
      }
      el.iocInput.value = item.ioc;
      handleIocInputDetection();
      runAnalysis(item.ioc);
    });

    el.historyContainer.appendChild(card);
  });
}

el.refreshHistoryBtn.addEventListener('click', loadSearchHistory);

// ============================================================================
// 3. LIVE RADAR / SCANNING MOTION & IOC ANALYSIS DISPATCH
// ============================================================================
el.analyzeForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const val = el.iocInput.value.trim();
  if (val) runAnalysis(val);
});

async function runAnalysis(iocString) {
  const rawClean = iocString.replace(/\[\.\]/g, '.').trim();
  if (REGEX.rfc1918.test(rawClean)) {
    showToast(
      'PERIMETER WARNING',
      `RFC1918 / Loopback IP (${rawClean}) cannot be enriched via public threat feeds.`,
      'error',
      6000
    );
    return;
  }

  if (state.detectedType && state.detectedType !== 'unknown' && state.detectedType !== state.activePillar) {
    switchPillar(state.detectedType);
    showToast('PILLAR ALIGNED', `Auto-aligned active console to [${state.detectedType.toUpperCase()}].`, 'info', 2500);
  }

  el.analyzeSubmitBtn.disabled = true;
  el.analyzeBtnIcon.classList.add('hidden');
  el.analyzeSpinner.classList.remove('hidden');
  el.analyzeBtnText.textContent = 'SCANNING...';

  el.inputContainerWrapper.classList.add('border-indigo-500/60', 'ring-2', 'ring-indigo-500/20');

  el.resultsSection.classList.add('hidden');
  el.scanningLoader.classList.remove('hidden');
  el.scanningLoader.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const result = await apiRequest('/api/analyze', {
      method: 'POST',
      body: { ioc: iocString },
    });

    state.lastAnalysis = result;
    currentAnalysisData = result;
    renderAnalysisResults(result);

    await loadSearchHistory();
    showToast('TELEMETRY CORRELATED', `Indicator [${result.defanged_ioc}] successfully enriched.`, 'success');
  } catch (error) {
    showToast('SCAN FAILED', error.message, 'error', 5500);
  } finally {
    el.analyzeSubmitBtn.disabled = false;
    el.analyzeBtnIcon.classList.remove('hidden');
    el.analyzeSpinner.classList.add('hidden');
    el.analyzeBtnText.textContent = 'INITIATE SCAN';
    el.inputContainerWrapper.classList.remove('border-indigo-500/60', 'ring-2', 'ring-indigo-500/20');
    el.scanningLoader.classList.add('hidden');
  }
}

// ============================================================================
// 4. DYNAMIC RISK GAUGE & RESULTS DOSSIER (WITH MITRE & MULTI-FACTOR METER)
// ============================================================================
function renderAnalysisResults(data) {
  currentAnalysisData = data;
  el.resultsSection.classList.remove('hidden');

  // 1. Header Information
  el.resultIocTypePill.textContent = (data.ioc_type || 'IOC').toUpperCase();
  el.resultDefangedIoc.textContent = data.defanged_ioc || data.original_ioc;
  el.resultOriginalIoc.textContent = data.original_ioc;
  el.resultClassificationLabel.textContent = `${data.classification} [${data.severity}]`;

  // 2. Animate Dynamic SVG Risk Gauge
  const score = Math.max(0, Math.min(100, Number(data.threat_score || 0)));
  animateThreatGauge(score, data.severity);

  // Legacy Breakdown Text
  if (data.score_breakdown) {
    const vtPts = data.score_breakdown.virustotal_component || 0;
    const feed2Pts = data.score_breakdown.vendor2_component || 0;
    const feed2Name = data.ioc_type === 'ip' ? 'AbuseIPDB' : data.ioc_type === 'hash' ? 'MalwareBazaar' : 'URLhaus';
    el.resultScoreBreakdown.textContent = `VT: ${vtPts} pts • ${feed2Name}: ${feed2Pts} pts`;
  }

  // 3. Task 3.2: Multi-Factor Contextual Risk Breakdown Card
  renderMultiFactorBreakdown(data);

  // 4. Task 3.2: MITRE ATT&CK Matrix Grid
  renderMitreMatrix(data.mitre_techniques || []);

  // 5. VirusTotal Telemetry Card
  renderVirusTotalDossier(data.raw_metrics?.virustotal || {});

  // 6. Secondary Provider Telemetry Card
  renderSecondaryProviderDossier(data.ioc_type, data.raw_metrics);

  // 7. SOC Playbook Checklist
  renderContainmentPlaybook(data.recommended_actions || []);

  el.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateThreatGauge(targetScore, severity) {
  const circumference = 314;
  const targetOffset = circumference - (targetScore / 100) * circumference;

  el.gaugeCircleProgress.classList.remove('stroke-emerald-400', 'stroke-amber-400', 'stroke-rose-500');
  el.resultThreatScore.classList.remove('text-emerald-400', 'text-amber-400', 'text-rose-500');
  el.resultSeverityBadge.className = 'px-4 py-1.5 rounded-full font-mono text-xs font-extrabold uppercase tracking-wider border';

  if (severity === 'High') {
    el.gaugeCircleProgress.classList.add('stroke-rose-500');
    el.resultThreatScore.classList.add('text-rose-500');
    el.resultSeverityBadge.classList.add('bg-rose-500/10', 'text-rose-400', 'border-rose-500/30', 'shadow-neon-crimson');
    el.resultSeverityBadge.textContent = 'MALICIOUS [HIGH RISK]';
  } else if (severity === 'Medium') {
    el.gaugeCircleProgress.classList.add('stroke-amber-400');
    el.resultThreatScore.classList.add('text-amber-400');
    el.resultSeverityBadge.classList.add('bg-amber-500/10', 'text-amber-400', 'border-amber-500/30', 'shadow-neon-amber');
    el.resultSeverityBadge.textContent = 'SUSPICIOUS [MEDIUM RISK]';
  } else {
    el.gaugeCircleProgress.classList.add('stroke-emerald-400');
    el.resultThreatScore.classList.add('text-emerald-400');
    el.resultSeverityBadge.classList.add('bg-emerald-500/10', 'text-emerald-400', 'border-emerald-500/30', 'shadow-neon-emerald');
    el.resultSeverityBadge.textContent = 'CLEAN [BENIGN PROFILE]';
  }

  el.gaugeCircleProgress.style.strokeDashoffset = targetOffset;

  const startTime = performance.now();
  const duration = 1000;

  function countUp(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const currentVal = (progress * targetScore).toFixed(1);
    el.resultThreatScore.textContent = currentVal;

    if (progress < 1) {
      requestAnimationFrame(countUp);
    } else {
      el.resultThreatScore.textContent = targetScore.toFixed(1);
    }
  }

  requestAnimationFrame(countUp);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Task 3.2: Multi-Factor Breakdown Card Renderer (Engineered 4-Factor SOC Architecture)
function renderMultiFactorBreakdown(data) {
  const bd = data.score_breakdown || {};
  const factors = bd.factors || bd;

  // Card 1: Multi-Vendor Consensus & Reliability Matrix (35% Weight / Max 35.0 pts)
  const consensusObj = factors.vendor_consensus || factors.cross_vendor_consensus || factors.external_engines || {};
  const consensusScore = bd.vendor_consensus !== undefined 
    ? Number(bd.vendor_consensus) 
    : (bd.cross_vendor_consensus !== undefined ? Number(bd.cross_vendor_consensus) : Number(consensusObj.score || 0));
  const consensusPct = Math.min(100, Math.max(0, (consensusScore / 35.0) * 100));
  el.meterEngineBar.style.width = `${consensusPct.toFixed(1)}%`;
  el.meterEngineVal.textContent = `${consensusScore.toFixed(1)} / 35.0 pts`;
  const consensusDetail = consensusObj.details || (data.raw_metrics?.virustotal ? `VT: ${data.raw_metrics.virustotal.malicious || 0}/${data.raw_metrics.virustotal.total || 0} engines` : 'Cross-vendor consensus evaluated');
  el.meterEngineDetail.innerHTML = `<span class="truncate flex-1 mr-2" title="${escapeHtml(consensusDetail)}">${escapeHtml(consensusDetail)}</span><span class="shrink-0 font-semibold text-slate-500">Max: 35 pts</span>`;

  if (el.meterConsensusBadge) {
    const verdict = consensusObj.consensus_verdict || (consensusScore >= 20 ? 'Corroborated' : consensusScore > 0 ? 'Partial Flag' : 'Clean');
    el.meterConsensusBadge.textContent = verdict.toUpperCase();
    if (verdict.toLowerCase().includes('corroborated') || verdict.toLowerCase().includes('av consensus')) {
      el.meterConsensusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30 shrink-0';
    } else if (verdict.toLowerCase().includes('isolated') || verdict.toLowerCase().includes('low') || verdict.toLowerCase().includes('flag')) {
      el.meterConsensusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30 shrink-0';
    } else {
      el.meterConsensusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0';
    }
  }

  // Card 2: Threat Taxonomy & Classification (30% Weight / Max 30.0 pts)
  const taxonomyObj = factors.threat_taxonomy || factors.threat_category || {};
  const taxonomyScore = bd.threat_taxonomy !== undefined 
    ? Number(bd.threat_taxonomy) 
    : (bd.threat_category !== undefined ? Number(bd.threat_category) : Number(taxonomyObj.score || 0));
  const taxonomyPct = Math.min(100, Math.max(0, (taxonomyScore / 30.0) * 100));
  el.meterThreatBar.style.width = `${taxonomyPct.toFixed(1)}%`;
  el.meterThreatVal.textContent = `${taxonomyScore.toFixed(1)} / 30.0 pts`;
  const taxonomyDetail = taxonomyObj.details || (taxonomyObj.flags?.length ? taxonomyObj.flags.join(', ') : 'No adversary threat tags reported by threat feeds');
  el.meterThreatDetail.innerHTML = `<span class="truncate flex-1 mr-2" title="${escapeHtml(taxonomyDetail)}">${escapeHtml(taxonomyDetail)}</span><span class="shrink-0 font-semibold text-slate-500">Max: 30 pts</span>`;

  if (el.meterTaxonomyBadge) {
    if (taxonomyObj.malware_families && taxonomyObj.malware_families.length) {
      el.meterTaxonomyBadge.textContent = taxonomyObj.malware_families[0].toUpperCase();
      el.meterTaxonomyBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/15 text-rose-300 border border-rose-500/40 shrink-0 shadow-neon-crimson';
    } else if (taxonomyScore >= 25) {
      el.meterTaxonomyBadge.textContent = 'CRITICAL TTP';
      el.meterTaxonomyBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30 shrink-0';
    } else if (taxonomyScore >= 15) {
      el.meterTaxonomyBadge.textContent = 'SUSPICIOUS';
      el.meterTaxonomyBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30 shrink-0';
    } else if (taxonomyScore > 0) {
      el.meterTaxonomyBadge.textContent = 'RECON';
      el.meterTaxonomyBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-blue-500/10 text-blue-400 border border-blue-500/30 shrink-0';
    } else {
      el.meterTaxonomyBadge.textContent = 'BENIGN';
      el.meterTaxonomyBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0';
    }
  }

  // Card 3: Infrastructure, Network & ASN Telemetry (25% Weight / Max 25.0 pts)
  const infraObj = factors.infrastructure_telemetry || factors.reputation_confidence || factors.confidence_prevalence || {};
  let infraScore = (typeof infraObj.score === 'number') 
    ? infraObj.score 
    : (bd.infrastructure_telemetry !== undefined 
      ? Number(bd.infrastructure_telemetry) 
      : (bd.infrastructure_telemetry_score !== undefined 
        ? Number(bd.infrastructure_telemetry_score) 
        : (bd.reputation_confidence !== undefined ? Number(bd.reputation_confidence) : Number(infraObj.score || 0))));

  const netType = (infraObj.network_type || '').toLowerCase();
  const isBenignOrNA = (infraScore === 0) || (data.ioc_type === 'hash') || (infraObj.asn === 'N/A' && netType.includes('n/a')) || netType.includes('benign');
  if (isBenignOrNA) {
    infraScore = 0.0;
  }
  const infraPct = Math.min(100, Math.max(0, (infraScore / 25.0) * 100));
  el.meterConfidenceBar.style.width = `${infraPct.toFixed(1)}%`;
  el.meterConfidenceVal.textContent = `${infraScore.toFixed(1)} / 25.0 pts`;
  const infraDetail = infraObj.details || 'Infrastructure telemetry evaluated';
  el.meterConfidenceDetail.innerHTML = `<span class="truncate flex-1 mr-2" title="${escapeHtml(infraDetail)}">${escapeHtml(infraDetail)}</span><span class="shrink-0 font-semibold text-slate-500">Max: 25 pts</span>`;

  if (el.meterInfraBadge) {
    if (data.ioc_type === 'hash') {
      el.meterInfraBadge.textContent = 'FILE ARTIFACT';
    } else if (infraObj.asn && infraObj.asn !== 'N/A') {
      const geoFlag = infraObj.country_flag ? ` ${infraObj.country_flag}` : '';
      el.meterInfraBadge.textContent = `${infraObj.asn}${geoFlag}`;
    } else if (infraObj.network_type) {
      el.meterInfraBadge.textContent = infraObj.network_type.split(' ')[0].toUpperCase();
    } else {
      el.meterInfraBadge.textContent = 'ASN / GEO';
    }

    if (infraScore >= 18) {
      el.meterInfraBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30 shrink-0';
    } else if (infraScore > 0) {
      el.meterInfraBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/30 shrink-0';
    } else {
      el.meterInfraBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0';
    }
  }

  // Card 4: Structural & Heuristic Anomalies (10% Weight / Max 10.0 pts)
  const heurObj = factors.structural_heuristics || factors.attribute_heuristics || {};
  const heurScore = bd.structural_heuristics !== undefined 
    ? Number(bd.structural_heuristics) 
    : (bd.attribute_heuristics !== undefined ? Number(bd.attribute_heuristics) : Number(heurObj.score || 0));
  const heurPct = Math.min(100, Math.max(0, (heurScore / 10.0) * 100));
  el.meterHeuristicsBar.style.width = `${heurPct.toFixed(1)}%`;
  el.meterHeuristicsVal.textContent = `${heurScore.toFixed(1)} / 10.0 pts`;
  const heurDetail = heurObj.details || (heurObj.anomalies?.length ? heurObj.anomalies.join(', ') : 'No structural anomalies detected');
  el.meterHeuristicsDetail.innerHTML = `<span class="truncate flex-1 mr-2" title="${escapeHtml(heurDetail)}">${escapeHtml(heurDetail)}</span><span class="shrink-0 font-semibold text-slate-500">Max: 10 pts</span>`;

  if (el.meterHeuristicsBadge) {
    if (heurObj.anomalies && heurObj.anomalies.length) {
      el.meterHeuristicsBadge.textContent = `${heurObj.anomalies.length} ${heurObj.anomalies.length === 1 ? 'ANOMALY' : 'ANOMALIES'}`;
      el.meterHeuristicsBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30 shrink-0';
    } else {
      const checksCount = heurObj.checks_evaluated ? heurObj.checks_evaluated.length : 2;
      el.meterHeuristicsBadge.textContent = `${checksCount} CHECKS PASS`;
      el.meterHeuristicsBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0';
    }
  }

  // Verdict Badge Styling
  const verdict = data.verdict || (data.threat_score >= 85 ? 'Critical' : data.threat_score >= 60 ? 'High' : data.threat_score >= 20 ? 'Medium' : 'Low');
  el.multifactorVerdictBadge.textContent = `VERDICT: ${verdict.toUpperCase()}`;

  if (verdict === 'Critical') {
    el.multifactorVerdictBadge.className = 'self-start sm:self-auto px-3 py-1 rounded-lg font-mono text-xs font-extrabold border uppercase bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-neon-crimson';
  } else if (verdict === 'High') {
    el.multifactorVerdictBadge.className = 'self-start sm:self-auto px-3 py-1 rounded-lg font-mono text-xs font-extrabold border uppercase bg-rose-500/10 text-rose-400 border-rose-500/30';
  } else if (verdict === 'Medium') {
    el.multifactorVerdictBadge.className = 'self-start sm:self-auto px-3 py-1 rounded-lg font-mono text-xs font-extrabold border uppercase bg-amber-500/10 text-amber-400 border-amber-500/30';
  } else {
    el.multifactorVerdictBadge.className = 'self-start sm:self-auto px-3 py-1 rounded-lg font-mono text-xs font-extrabold border uppercase bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  }
}

// ============================================================================
// Task 3.2: RISK FACTOR DRILLDOWN MODAL CONTROLLER
// Interactive detail inspection for the 4 Multi-Factor Risk Score cards
// ============================================================================
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freqs = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freqs) {
    const p = freqs[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function closeRiskDrilldownModal() {
  if (el.riskDrilldownModal) {
    el.riskDrilldownModal.classList.add('hidden');
  }
}

function openRiskDrilldownModal(factorIndex) {
  const data = currentAnalysisData || state.lastAnalysis;
  if (!data) {
    showToast('NO ACTIVE ANALYSIS', 'Please initiate a scan on an IOC to inspect risk factors.', 'info');
    return;
  }

  const bd = data.score_breakdown || {};
  const factors = bd.factors || bd;

  if (!el.riskDrilldownModal || !el.drilldownContent) return;

  // Clear previous modal content
  el.drilldownContent.innerHTML = '';

  if (factorIndex === 1) {
    // FACTOR 1: Multi-Vendor Consensus & Reliability Matrix (35% Weight / Max 35.0 pts)
    const consensusObj = factors.vendor_consensus || factors.cross_vendor_consensus || factors.external_engines || {};
    const score = bd.vendor_consensus !== undefined 
      ? Number(bd.vendor_consensus) 
      : (bd.cross_vendor_consensus !== undefined ? Number(bd.cross_vendor_consensus) : Number(consensusObj.score || 0));
    const maxPts = 35.0;
    const verdict = consensusObj.consensus_verdict || (score >= 20 ? 'Corroborated Malicious' : score > 0 ? 'Partial Flag' : 'Unanimously Clean');
    const dampenerApplied = !!consensusObj.dampener_applied;
    const agreeingFeeds = consensusObj.agreeing_feeds || [];
    const details = consensusObj.details || 'Cross-vendor consensus evaluated across independent threat intelligence feeds.';

    // Header updates
    el.drilldownFactorNum.textContent = 'FACTOR 1 (35% WEIGHT)';
    el.drilldownFactorNum.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/40';
    el.drilldownTitle.textContent = 'Multi-Vendor Consensus & Reliability Matrix';
    el.drilldownSubtitle.textContent = 'Cross-vendor consensus, independent feed corroboration, and false-positive dampener telemetry';
    el.drilldownFactorPts.textContent = `${score.toFixed(1)} / ${maxPts.toFixed(1)} pts`;

    if (verdict.toLowerCase().includes('corroborated') || verdict.toLowerCase().includes('av consensus')) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-neon-crimson';
    } else if (verdict.toLowerCase().includes('isolated') || verdict.toLowerCase().includes('low') || verdict.toLowerCase().includes('flag')) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-neon-amber';
    } else {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-neon-emerald';
    }
    el.drilldownBadge.textContent = verdict.toUpperCase();

    // VirusTotal Metrics
    const vt = data.raw_metrics?.virustotal || {};
    const vtMalicious = Number(vt.malicious || 0);
    const vtSuspicious = Number(vt.suspicious || 0);
    const vtHarmless = Number(vt.harmless || 0);
    const vtUndetected = Number(vt.undetected || 0);
    const vtTotal = Number(vt.total || (vtMalicious + vtSuspicious + vtHarmless + vtUndetected) || 0);

    // Secondary Provider Metrics
    let secName = 'Secondary Feed';
    let secVerdict = 'Clean / Unlisted';
    let secDetails = '';
    let secFlagged = false;

    if (data.ioc_type === 'ip') {
      secName = 'AbuseIPDB';
      const abuse = data.raw_metrics?.abuseipdb || {};
      const conf = Number(abuse.abuse_confidence_score || 0);
      const reports = Number(abuse.total_reports || 0);
      secFlagged = conf >= 20 || reports >= 5;
      secVerdict = secFlagged ? `Flagged (${conf}% Confidence, ${reports} Reports)` : `Clean (${conf}% Confidence)`;
      secDetails = `ISP: ${abuse.isp || 'N/A'} • Usage: ${abuse.usage_type || 'N/A'} • Tor: ${abuse.is_tor ? 'YES' : 'NO'}`;
    } else if (data.ioc_type === 'domain' || data.ioc_type === 'url') {
      secName = 'URLhaus (abuse.ch)';
      const uh = data.raw_metrics?.urlhaus || {};
      secFlagged = Boolean(uh.active_threat || uh.urlhaus_status === 'active' || uh.urlhaus_status === 'online' || Number(uh.url_count || 0) > 0);
      secVerdict = secFlagged ? `Flagged [${uh.threat || 'Malware Host'}]` : 'Clean / Offline';
      secDetails = `Status: ${uh.urlhaus_status || 'unlisted'} • Active URLs: ${uh.url_count || 0} • Reporter: ${uh.reporter || 'N/A'}`;
    } else if (data.ioc_type === 'hash') {
      secName = 'MalwareBazaar (abuse.ch)';
      const mb = data.raw_metrics?.malwarebazaar || {};
      secFlagged = Boolean(mb.confirmed);
      secVerdict = secFlagged ? `Confirmed Malware [${mb.signature || 'Malicious'}]` : 'Clean / Unconfirmed';
      secDetails = `Type: ${mb.file_type || 'N/A'} • Delivery: ${mb.delivery_method || 'N/A'} • First Seen: ${mb.first_seen || 'N/A'}`;
    }

    el.drilldownContent.innerHTML = `
      <!-- Verdict & Telemetry Banner -->
      <div class="p-3.5 bg-[#0D111A]/80 border border-white/[0.08] rounded-xl space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-slate-400 font-bold">Consensus Verdict:</span>
          <span class="font-extrabold text-indigo-300 text-sm">${escapeHtml(verdict)}</span>
        </div>
        <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(details)}</p>
      </div>

      ${dampenerApplied ? `
      <!-- False Positive Dampener Alert -->
      <div class="p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-xl space-y-1.5 shadow-neon-amber">
        <div class="flex items-center gap-2 text-amber-300 font-bold">
          <svg class="w-4 h-4 shrink-0 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <span>FALSE-POSITIVE DAMPENER ACTIVE</span>
        </div>
        <p class="text-[11px] text-amber-200/90 leading-relaxed">
          An isolated vendor flag (1 out of ${vtTotal} AV engines) was evaluated. Because ${Math.max(0, vtTotal - vtMalicious)}+ independent engines and secondary intelligence providers reported clean, this isolated flag was dampened to <strong>0.0 pts</strong> to prevent false SOC alarms.
        </p>
      </div>` : ''}

      <!-- Cross-Vendor Corroboration Breakdown -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Independent Feed Correlation</div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          
          <!-- Feed 1: VirusTotal -->
          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-indigo-400 flex items-center gap-1.5">
                <span>🛡️</span> VirusTotal
              </span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${vtMalicious > 0 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}">
                ${vtMalicious}/${vtTotal} FLAGGED
              </span>
            </div>
            <div class="grid grid-cols-2 gap-1.5 text-[11px] text-slate-300 pt-1">
              <div><span class="text-slate-500">Malicious:</span> <span class="font-bold ${vtMalicious > 0 ? 'text-rose-400' : 'text-slate-300'}">${vtMalicious}</span></div>
              <div><span class="text-slate-500">Suspicious:</span> <span class="font-bold text-amber-400">${vtSuspicious}</span></div>
              <div><span class="text-slate-500">Harmless:</span> <span class="font-bold text-emerald-400">${vtHarmless}</span></div>
              <div><span class="text-slate-500">Undetected:</span> <span class="font-bold text-slate-400">${vtUndetected}</span></div>
            </div>
            <div class="text-[10px] text-slate-400 pt-1 border-t border-white/[0.06]">
              Reputation: <strong class="text-indigo-300">${vt.reputation !== undefined ? vt.reputation : 'N/A'}</strong>
            </div>
          </div>

          <!-- Feed 2: Secondary Provider -->
          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-indigo-400 flex items-center gap-1.5">
                <span>📡</span> ${escapeHtml(secName)}
              </span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${secFlagged ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}">
                ${secFlagged ? 'FLAGGED' : 'CLEAN'}
              </span>
            </div>
            <div class="text-[11px] text-slate-300">
              <span class="text-slate-500">Verdict:</span> <strong class="text-white">${escapeHtml(secVerdict)}</strong>
            </div>
            <div class="text-[10px] text-slate-400 pt-1 border-t border-white/[0.06] truncate" title="${escapeHtml(secDetails)}">
              ${escapeHtml(secDetails)}
            </div>
          </div>

        </div>
      </div>

      <!-- Reliability Weighting Rules Table -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Reliability Weighting &amp; Scoring Model</div>
        <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2 text-[11px]">
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300">Cross-Feed Corroboration Agreement:</span>
            <span class="font-bold text-indigo-400">${agreeingFeeds.length >= 2 ? '+15.0 pts (Awarded)' : '0.0 pts (Single or Zero Feeds)'}</span>
          </div>
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300">AV Engine Ratio Scaling (VirusTotal):</span>
            <span class="font-bold text-indigo-400">Scaled up to 20.0 pts</span>
          </div>
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300">Corroborated Threat Feeds:</span>
            <span class="font-bold text-white">${agreeingFeeds.length > 0 ? agreeingFeeds.join(', ') : 'None (Benign agreement)'}</span>
          </div>
          <div class="flex justify-between items-center pt-1 font-bold">
            <span class="text-slate-200">Total Factor 1 Contribution:</span>
            <span class="text-indigo-400 text-xs">${score.toFixed(1)} / 35.0 pts</span>
          </div>
        </div>
      </div>
    `;

  } else if (factorIndex === 2) {
    // FACTOR 2: Threat Taxonomy & Classification (30% Weight / Max 30.0 pts)
    const taxonomyObj = factors.threat_taxonomy || factors.threat_category || {};
    const score = bd.threat_taxonomy !== undefined 
      ? Number(bd.threat_taxonomy) 
      : (bd.threat_category !== undefined ? Number(bd.threat_category) : Number(taxonomyObj.score || 0));
    const maxPts = 30.0;
    const malwareFamilies = taxonomyObj.malware_families || [];
    const flags = taxonomyObj.flags || taxonomyObj.attack_categories || [];
    const severityTier = taxonomyObj.severity_tier || (score >= 25 ? 'Critical (30 pts)' : score >= 15 ? 'Suspicious (15 pts)' : score > 0 ? 'Reconnaissance' : 'Clean (0 pts)');
    const details = taxonomyObj.details || 'No adversary threat tags reported by threat feeds';

    // Header info
    el.drilldownFactorNum.textContent = 'FACTOR 2 (30% WEIGHT)';
    el.drilldownFactorNum.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40';
    el.drilldownTitle.textContent = 'Threat Taxonomy & Classification';
    el.drilldownSubtitle.textContent = 'Parsed adversary threat tags, detected malware families, and taxonomy classification rules';
    el.drilldownFactorPts.textContent = `${score.toFixed(1)} / ${maxPts.toFixed(1)} pts`;

    if (score >= 25) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-neon-crimson';
    } else if (score >= 15) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-neon-amber';
    } else if (score > 0) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/40';
    } else {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-neon-emerald';
    }
    el.drilldownBadge.textContent = severityTier.toUpperCase();

    // Families Chips
    const familiesHtml = malwareFamilies.length > 0
      ? `<div class="flex flex-wrap gap-2">${malwareFamilies.map(f => `
          <span class="px-3 py-1 bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded-lg font-bold text-xs flex items-center gap-1.5 shadow-neon-crimson">
            <span>☣️</span>
            <span>${escapeHtml(f.toUpperCase())}</span>
          </span>`).join('')}</div>`
      : `<div class="p-3 bg-[#0B0F19] border border-emerald-500/20 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
          <span>✓</span>
          <span>No specific malware family signatures identified across active feeds.</span>
        </div>`;

    // Flags Chips
    const flagsHtml = flags.length > 0
      ? `<div class="flex flex-wrap gap-2">${flags.map(tag => {
          const lower = tag.toLowerCase();
          const isCrit = ['ransomware', 'c2', 'botnet', 'stealer', 'trojan', 'exploit'].some(t => lower.includes(t));
          const cls = isCrit ? 'bg-rose-500/15 text-rose-300 border-rose-500/40' : 'bg-amber-500/15 text-amber-300 border-amber-500/40';
          return `<span class="px-2.5 py-1 rounded-lg border text-xs font-bold ${cls}">● ${escapeHtml(tag)}</span>`;
        }).join('')}</div>`
      : `<div class="p-3 bg-[#0B0F19] border border-emerald-500/20 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
          <span>✓</span>
          <span>No malicious adversary threat tags reported (Benign profile).</span>
        </div>`;

    el.drilldownContent.innerHTML = `
      <!-- Summary Banner -->
      <div class="p-3.5 bg-[#0D111A]/80 border border-rose-500/20 rounded-xl space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-slate-400 font-bold">Severity Tier:</span>
          <span class="font-extrabold text-rose-400 text-sm">${escapeHtml(severityTier)}</span>
        </div>
        <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(details)}</p>
      </div>

      <!-- Detected Malware Families -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <span>Corroborated Malware Families</span>
          <span class="text-[10px] text-slate-500 font-normal">(${malwareFamilies.length} detected)</span>
        </div>
        ${familiesHtml}
      </div>

      <!-- Adversary Attack Categories & TTP Flags -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <span>Adversary Attack Categories &amp; TTP Flags</span>
          <span class="text-[10px] text-slate-500 font-normal">(${flags.length} detected)</span>
        </div>
        ${flagsHtml}
      </div>

      <!-- Taxonomy Classification Scoring Rules -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Taxonomy Scoring Matrix &amp; Evaluation Rules</div>
        <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2 text-[11px]">
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300"><strong class="text-rose-400">Critical Tier (25–30 pts):</strong> Ransomware, C2, Botnet, Stealers (AgentTesla, Redline), Trojans</span>
            <span class="font-bold text-rose-400">25–30 pts</span>
          </div>
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300"><strong class="text-amber-400">Suspicious Tier (15 pts):</strong> Phishing, Malware Download, Cryptominer, Exploited Host</span>
            <span class="font-bold text-amber-400">15 pts</span>
          </div>
          <div class="flex justify-between items-center pb-1.5 border-b border-white/[0.06]">
            <span class="text-slate-300"><strong class="text-blue-400">Reconnaissance Tier (5–10 pts):</strong> Port Scanner, SSH Brute-Force, Bad Bot, Spam</span>
            <span class="font-bold text-blue-400">5–10 pts</span>
          </div>
          <div class="flex justify-between items-center pt-1 font-bold">
            <span class="text-slate-200">Total Factor 2 Contribution:</span>
            <span class="text-rose-400 text-xs">${score.toFixed(1)} / 30.0 pts</span>
          </div>
        </div>
      </div>
    `;

  } else if (factorIndex === 3) {
    // FACTOR 3: Infrastructure, Network & ASN Telemetry (25% Weight / Max 25.0 pts)
    const infraObj = factors.infrastructure_telemetry || factors.reputation_confidence || {};
    let score = (typeof infraObj.score === 'number') 
      ? infraObj.score 
      : (bd.infrastructure_telemetry !== undefined 
        ? Number(bd.infrastructure_telemetry) 
        : (bd.infrastructure_telemetry_score !== undefined 
          ? Number(bd.infrastructure_telemetry_score) 
          : (bd.reputation_confidence !== undefined ? Number(bd.reputation_confidence) : Number(infraObj.score || 0))));
    const maxPts = 25.0;
    const telemetry = (infraObj.telemetry && Object.keys(infraObj.telemetry).length > 0) ? infraObj.telemetry : infraObj;
    const asn = telemetry.asn || 'N/A';
    const asOrg = telemetry.as_org || 'N/A';
    const country = telemetry.country || 'N/A';
    const countryFlag = telemetry.country_flag || '';
    const networkType = telemetry.network_type || 'Benign network allocation';
    const registrar = telemetry.registrar || 'N/A';
    const riskFactors = telemetry.risk_factors || [];
    const details = infraObj.details || 'Infrastructure telemetry evaluated';

    const netLower = (networkType || '').toLowerCase();
    const isBenignOrNA = (score === 0) || (data.ioc_type === 'hash') || (asn === 'N/A' && netLower.includes('n/a')) || netLower.includes('benign');
    if (isBenignOrNA) {
      score = 0.0;
    }

    // Header info
    el.drilldownFactorNum.textContent = 'FACTOR 3 (25% WEIGHT)';
    el.drilldownFactorNum.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40';
    el.drilldownTitle.textContent = 'Infrastructure, Network & ASN Telemetry';
    el.drilldownSubtitle.textContent = 'Autonomous System (ASN), Geolocation, Hosting Infrastructure, and Network Classification';
    el.drilldownFactorPts.textContent = `${score.toFixed(1)} / ${maxPts.toFixed(1)} pts`;

    if (score >= 18) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-neon-crimson';
      el.drilldownBadge.textContent = `${asn} ${countryFlag}`.trim().toUpperCase();
    } else if (score > 0) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-neon-amber';
      el.drilldownBadge.textContent = `${asn} ${countryFlag}`.trim().toUpperCase();
    } else {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-neon-emerald';
      el.drilldownBadge.textContent = data.ioc_type === 'hash' ? 'N/A (FILE ARTIFACT)' : (asn !== 'N/A' ? `${asn} (BENIGN)` : 'BENIGN ALLOCATION');
    }

    // Risk factors badges
    const riskFactorsHtml = (riskFactors.length > 0 && score > 0)
      ? `<div class="space-y-1.5">${riskFactors.map(rf => `
          <div class="p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 font-mono text-xs flex items-center gap-2">
            <span class="text-amber-400">⚠️</span>
            <span>${escapeHtml(rf)}</span>
          </div>`).join('')}</div>`
      : `<div class="p-3 bg-[#0B0F19] border border-emerald-500/20 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
          <span>✓</span>
          <span>No anomalous infrastructure risks flagged. Benign network allocation. (0.0 / 25.0 pts)</span>
        </div>`;

    el.drilldownContent.innerHTML = `
      <!-- Summary Banner -->
      <div class="p-3.5 bg-[#0D111A]/80 border ${score > 0 ? 'border-amber-500/20' : 'border-emerald-500/20'} rounded-xl space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-slate-400 font-bold">Network Classification:</span>
          <span class="font-extrabold ${score > 0 ? 'text-amber-400' : 'text-emerald-400'} text-sm">${escapeHtml(networkType)}</span>
        </div>
        <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(details)}</p>
      </div>

      <!-- Structured Network Telemetry Grid -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Autonomous System &amp; Routing Topology</div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          
          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-1">
            <div class="text-[10px] text-slate-500 uppercase font-bold">Autonomous System (ASN)</div>
            <div class="font-extrabold text-indigo-400 text-sm">${escapeHtml(asn)}</div>
            <div class="text-[11px] text-slate-300 truncate" title="${escapeHtml(asOrg)}">${escapeHtml(asOrg)}</div>
          </div>

          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-1">
            <div class="text-[10px] text-slate-500 uppercase font-bold">Geolocation &amp; Jurisdiction</div>
            <div class="font-extrabold text-white text-sm flex items-center gap-2">
              <span>${escapeHtml(country || 'Global')}</span>
              <span class="text-base">${countryFlag}</span>
            </div>
            <div class="text-[11px] text-slate-400">Regional BGP Announcement</div>
          </div>

          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-1">
            <div class="text-[10px] text-slate-500 uppercase font-bold">Infrastructure Type</div>
            <div class="font-extrabold text-amber-300 text-sm">${escapeHtml(networkType)}</div>
            <div class="text-[10px] text-slate-400">Hosting &bull; VPS &bull; Residential</div>
          </div>

          <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-1">
            <div class="text-[10px] text-slate-500 uppercase font-bold">${data.ioc_type === 'hash' ? 'Registry / Sample Origin' : 'Domain Registrar'}</div>
            <div class="font-extrabold text-white text-sm truncate" title="${escapeHtml(registrar)}">${escapeHtml(registrar)}</div>
            <div class="text-[10px] text-slate-400">Verified Delegation Entity</div>
          </div>

        </div>
      </div>

      <!-- Identified Risk Factors -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Identified Infrastructure Risk Factors</div>
        ${riskFactorsHtml}
      </div>

      <!-- SOC Analysis Rationale -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">SOC Contextual Risk Rationale</div>
        <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2 text-[11px] text-slate-300 leading-relaxed">
          <p>
            Cloud and VPS hosting environments (AWS, DigitalOcean, OVH, Hetzner, Linode) conducting unexpected outbound connections carry significantly elevated intrinsic risk of automated adversary C2 staging or beaconing compared to residential or corporate campus networks.
          </p>
          <div class="flex justify-between items-center pt-2 border-t border-white/[0.06] font-bold">
            <span class="text-slate-200">Factor Contribution:</span>
            <span class="${score > 0 ? 'text-amber-400' : 'text-emerald-400'} text-xs">${score.toFixed(1)} / 25.0 pts</span>
          </div>
        </div>
      </div>
    `;

  } else if (factorIndex === 4) {
    // FACTOR 4: Structural & Heuristic Anomalies (10% Weight / Max 10.0 pts)
    const heurObj = factors.structural_heuristics || factors.attribute_heuristics || {};
    const score = bd.structural_heuristics !== undefined 
      ? Number(bd.structural_heuristics) 
      : (bd.attribute_heuristics !== undefined ? Number(bd.attribute_heuristics) : Number(heurObj.score || 0));
    const maxPts = 10.0;
    const anomalies = heurObj.anomalies || [];
    const checks = heurObj.checks_evaluated || [];
    const details = heurObj.details || 'Structural and heuristic anomalies evaluated';
    const iocStr = data.original_ioc || data.defanged_ioc || '';
    const iocEntropy = calculateShannonEntropy(iocStr);

    // Header info
    el.drilldownFactorNum.textContent = 'FACTOR 4 (10% WEIGHT)';
    el.drilldownFactorNum.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-violet-500/20 text-violet-300 border border-violet-500/40';
    el.drilldownTitle.textContent = 'Structural & Heuristic Anomalies';
    el.drilldownSubtitle.textContent = 'Heuristic pattern checks, format irregularities, and Shannon entropy analysis';
    el.drilldownFactorPts.textContent = `${score.toFixed(1)} / ${maxPts.toFixed(1)} pts`;

    if (anomalies.length > 0) {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-neon-crimson';
      el.drilldownBadge.textContent = `${anomalies.length} ${anomalies.length === 1 ? 'ANOMALY' : 'ANOMALIES'}`;
    } else {
      el.drilldownBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-neon-emerald';
      el.drilldownBadge.textContent = `${checks.length || 2} CHECKS PASS`;
    }

    // Checklist HTML
    const checksList = checks.length > 0 ? checks : ['Network Classification Check', 'Subnet Allocation & Routing Status', 'Format Syntax Validation'];
    const checklistHtml = checksList.map((chk) => {
      const isAnomaly = anomalies.some(a => a.toLowerCase().includes(chk.toLowerCase().slice(0, 10)) || chk.toLowerCase().includes('tor') || chk.toLowerCase().includes('data center') || chk.toLowerCase().includes('bogon') || chk.toLowerCase().includes('private'));
      return `
        <div class="p-2.5 bg-[#0B0F19] border border-white/[0.08] rounded-lg flex items-center justify-between text-[11px] gap-2">
          <span class="text-slate-200 font-medium">${escapeHtml(chk)}</span>
          <span class="px-2 py-0.5 rounded text-[9px] font-extrabold uppercase shrink-0 ${isAnomaly ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}">
            ${isAnomaly ? 'FLAGGED' : 'PASSED'}
          </span>
        </div>
      `;
    }).join('');

    // Check if artifact report exists with sections
    const artReport = state.lastArtifactReport;
    let artifactSectionHtml = '';
    if (artReport && artReport.sections && artReport.sections.length > 0) {
      artifactSectionHtml = `
        <div class="space-y-2 pt-2 border-t border-white/[0.08]">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Binary Section Shannon Entropy Analysis</span>
            <span class="text-[10px] text-indigo-400 font-bold">${artReport.sections.length} Sections Analyzed</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-[11px] text-left border-collapse">
              <thead>
                <tr class="border-b border-white/[0.08] text-slate-400 font-mono">
                  <th class="py-1.5 px-2">Section</th>
                  <th class="py-1.5 px-2">Raw Size</th>
                  <th class="py-1.5 px-2">Virtual Size</th>
                  <th class="py-1.5 px-2">Shannon Entropy</th>
                  <th class="py-1.5 px-2 text-right">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/[0.04] font-mono">
                ${artReport.sections.map(s => {
                  const isHigh = s.entropy >= 7.0;
                  const entColor = isHigh ? 'text-rose-400 font-extrabold' : s.entropy >= 6.0 ? 'text-amber-400 font-bold' : 'text-emerald-400';
                  return `
                    <tr>
                      <td class="py-1.5 px-2 font-bold text-white">${escapeHtml(s.name)}</td>
                      <td class="py-1.5 px-2 text-slate-400">${s.raw_size} B</td>
                      <td class="py-1.5 px-2 text-slate-400">${s.virtual_size} B</td>
                      <td class="py-1.5 px-2 ${entColor}">${s.entropy.toFixed(2)} / 8.0</td>
                      <td class="py-1.5 px-2 text-right">
                        <span class="px-1.5 py-0.5 rounded text-[9px] font-bold ${isHigh ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'}">
                          ${isHigh ? 'PACKED' : 'NORMAL'}
                        </span>
                      </td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    el.drilldownContent.innerHTML = `
      <!-- Summary Banner -->
      <div class="p-3.5 bg-[#0D111A]/80 border border-violet-500/20 rounded-xl space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-slate-400 font-bold">Heuristic Evaluation Status:</span>
          <span class="font-extrabold text-violet-400 text-sm">${anomalies.length > 0 ? `${anomalies.length} Structural Anomalies Detected` : 'All Heuristic Checks Passed'}</span>
        </div>
        <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(details)}</p>
      </div>

      <!-- Heuristic Checklist -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Executed Telemetry &amp; Anomaly Checks</div>
        <div class="space-y-1.5">
          ${checklistHtml}
        </div>
      </div>

      <!-- Indicator Entropy & Format Analysis -->
      <div class="space-y-2">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Indicator Complexity &amp; Shannon Entropy</div>
        <div class="p-3 bg-[#0B0F19] border border-white/[0.08] rounded-xl space-y-2.5">
          <div class="flex items-center justify-between text-xs">
            <span class="text-slate-300">Shannon Entropy (Complexity Index):</span>
            <span class="font-extrabold text-indigo-400">${iocEntropy.toFixed(3)} / 8.000 bits/byte</span>
          </div>
          <div class="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-white/[0.08]">
            <div class="h-full bg-indigo-500 transition-all duration-700" style="width: ${Math.min(100, (iocEntropy / 8.0) * 100).toFixed(1)}%"></div>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px] text-slate-400 pt-1">
            <div><span class="text-slate-500">Length:</span> <strong class="text-slate-200">${iocStr.length} chars</strong></div>
            <div><span class="text-slate-500">Pillar Type:</span> <strong class="text-slate-200">${(data.ioc_type || 'N/A').toUpperCase()}</strong></div>
            <div><span class="text-slate-500">Entropy Tier:</span> <strong class="${iocEntropy > 6.0 ? 'text-amber-400' : 'text-emerald-400'}">${iocEntropy > 6.0 ? 'High Complexity' : 'Normal'}</strong></div>
          </div>
        </div>
      </div>

      <!-- Per-Section Shannon Entropy for Artifacts if available -->
      ${artifactSectionHtml}

      <div class="pt-2 text-[10px] text-slate-500 italic">
        * Static binaries (.exe, .dll, .bin) uploaded to the [Binary &amp; Static Artifact Analysis] module provide complete byte-by-byte per-section Shannon entropy mapping and IAT hooking tables.
      </div>
    `;
  }

  // Display modal
  el.riskDrilldownModal.classList.remove('hidden');
}

// Wire Event Listeners for Risk Factor Interactive Cards & Modal
if (el.cardFactor1) el.cardFactor1.addEventListener('click', () => openRiskDrilldownModal(1));
if (el.cardFactor2) el.cardFactor2.addEventListener('click', () => openRiskDrilldownModal(2));
if (el.cardFactor3) el.cardFactor3.addEventListener('click', () => openRiskDrilldownModal(3));
if (el.cardFactor4) el.cardFactor4.addEventListener('click', () => openRiskDrilldownModal(4));

if (el.drilldownCloseBtn) el.drilldownCloseBtn.addEventListener('click', closeRiskDrilldownModal);
if (el.drilldownCloseBtnBottom) el.drilldownCloseBtnBottom.addEventListener('click', closeRiskDrilldownModal);

if (el.riskDrilldownModal) {
  el.riskDrilldownModal.addEventListener('click', (e) => {
    if (e.target === el.riskDrilldownModal) {
      closeRiskDrilldownModal();
    }
  });
}

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && el.riskDrilldownModal && !el.riskDrilldownModal.classList.contains('hidden')) {
    closeRiskDrilldownModal();
  }
});

// Task 3.2: MITRE ATT&CK Matrix Grid Renderer
function renderMitreMatrix(techniques) {
  el.mitreMatrixGrid.innerHTML = '';
  el.mitreCountBadge.textContent = `${techniques.length} ${techniques.length === 1 ? 'TECHNIQUE' : 'TECHNIQUES'} MAPPED`;

  if (!techniques || techniques.length === 0) {
    el.mitreMatrixGrid.innerHTML = `
      <div class="col-span-full p-4 border border-dashed border-white/[0.08] rounded-xl text-center font-mono text-xs text-slate-400">
        NO SPECIFIC MITRE ATT&CK TECHNIQUES MAPPED FOR THIS BENIGN TELEMETRY PROFILE
      </div>
    `;
    return;
  }

  techniques.forEach((tech) => {
    const card = document.createElement('div');
    card.className = 'p-3.5 bg-[#0D111A]/80 hover:bg-[#131926] border border-white/[0.08] hover:border-white/[0.16] rounded-xl transition-all space-y-2 group shadow-sm';

    // Tactic color badges
    let tacticColor = 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
    const tacticLower = (tech.tactic || '').toLowerCase();
    if (tacticLower.includes('command') || tacticLower.includes('c2')) {
      tacticColor = 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30';
    } else if (tacticLower.includes('initial') || tacticLower.includes('phish')) {
      tacticColor = 'bg-violet-500/15 text-violet-300 border-violet-500/30';
    } else if (tacticLower.includes('execution')) {
      tacticColor = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    } else if (tacticLower.includes('defense') || tacticLower.includes('injection')) {
      tacticColor = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    } else if (tacticLower.includes('reconnaissance')) {
      tacticColor = 'bg-sky-500/15 text-sky-300 border-sky-500/30';
    }

    const mitreUrl = `https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}/`;

    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <a href="${mitreUrl}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-600 hover:text-white transition-colors flex items-center gap-1" title="View Technique on MITRE ATT&CK">
          <span>${tech.technique_id}</span>
          <svg class="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
        </a>
        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase ${tacticColor}">
          ${tech.tactic}
        </span>
      </div>

      <div>
        <h4 class="text-xs font-semibold text-white font-mono group-hover:text-indigo-300 transition-colors">
          ${tech.technique_name}
        </h4>
        <p class="text-[11px] font-mono text-slate-300 mt-1 leading-relaxed bg-[#07090E]/60 p-2 rounded-lg border border-white/[0.06]">
          ${tech.reason || 'Adversary technique correlated via threat intelligence telemetry.'}
        </p>
      </div>
    `;

    el.mitreMatrixGrid.appendChild(card);
  });
}

function renderVirusTotalDossier(vt) {
  el.vtStatusPill.textContent = (vt.status || 'SUCCESS').toUpperCase();
  if (vt.status === 'success') {
    el.vtStatusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
  } else {
    el.vtStatusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-transparent text-slate-400 border border-white/[0.08]';
  }

  const mal = vt.malicious || 0;
  const susp = vt.suspicious || 0;
  const harm = vt.harmless || 0;
  const undet = vt.undetected || 0;
  const total = vt.total || mal + susp + harm + undet || 1;

  el.vtDetectionsText.textContent = `${mal} / ${total} AV Engines Flagged Threat`;

  el.vtBarMalicious.style.width = `${((mal / total) * 100).toFixed(1)}%`;
  el.vtBarSuspicious.style.width = `${((susp / total) * 100).toFixed(1)}%`;
  el.vtBarHarmless.style.width = `${((harm / total) * 100).toFixed(1)}%`;
  el.vtBarUndetected.style.width = `${((undet / total) * 100).toFixed(1)}%`;

  el.vtReputation.textContent = vt.reputation !== undefined ? vt.reputation : '0';
  el.vtOwner.textContent = vt.as_owner || vt.registrar || vt.meaningful_name || 'N/A';
  el.vtCountry.textContent = vt.country || 'Global / Unspecified';
}

function renderSecondaryProviderDossier(iocType, metrics) {
  el.vendor2Content.innerHTML = '';

  if (iocType === 'ip') {
    const abuse = metrics?.abuseipdb || {};
    el.vendor2Icon.textContent = 'AB';
    el.vendor2Title.textContent = 'AbuseIPDB v2 Telemetry';
    el.vendor2Subtitle.textContent = 'Network Reputation & Abuse Confidence';
    el.vendor2StatusPill.textContent = (abuse.status || 'SUCCESS').toUpperCase();

    const score = abuse.abuse_confidence_score || 0;
    const reports = abuse.total_reports || 0;
    const isp = abuse.isp || 'N/A';
    const domain = abuse.domain || 'N/A';
    const usage = abuse.usage_type || 'N/A';

    el.vendor2Content.innerHTML = `
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Abuse Confidence Score:</span>
        <span class="font-extrabold ${score > 50 ? 'text-rose-400' : 'text-slate-200'}">${score}%</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Total Abuse Reports:</span>
        <span class="text-slate-200 font-bold">${reports.toLocaleString()}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Upstream ISP:</span>
        <span class="text-slate-200 truncate max-w-[220px] font-semibold">${isp}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Host Domain:</span>
        <span class="text-slate-200 font-semibold">${domain}</span>
      </div>
      <div class="flex justify-between py-1.5">
        <span class="text-slate-400">Usage Classification:</span>
        <span class="text-slate-200 truncate max-w-[220px] font-semibold">${usage}</span>
      </div>
    `;
  } else if (iocType === 'domain' || iocType === 'url') {
    const urlhaus = metrics?.urlhaus || {};
    el.vendor2Icon.textContent = 'UH';
    el.vendor2Title.textContent = 'URLhaus (abuse.ch)';
    el.vendor2Subtitle.textContent = 'Malware URL & Host Tracking';
    el.vendor2StatusPill.textContent = (urlhaus.status || 'SUCCESS').toUpperCase();

    const statusTag = urlhaus.urlhaus_status || urlhaus.url_status || 'none';
    const threat = urlhaus.threat || (urlhaus.active_threat ? 'malware_download' : 'none');
    const count = urlhaus.url_count !== undefined ? urlhaus.url_count : 'N/A';
    const tags = Array.isArray(urlhaus.tags) && urlhaus.tags.length > 0 ? urlhaus.tags.join(', ') : 'None';

    el.vendor2Content.innerHTML = `
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">URLhaus Infrastructure State:</span>
        <span class="font-extrabold uppercase ${statusTag === 'active' || statusTag === 'online' ? 'text-rose-400' : 'text-slate-200'}">${statusTag}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Threat Signature:</span>
        <span class="text-slate-200 font-semibold">${threat}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Associated Payloads Count:</span>
        <span class="text-slate-200 font-bold">${count}</span>
      </div>
      <div class="flex justify-between py-1.5">
        <span class="text-slate-400">Threat Tags:</span>
        <span class="text-slate-200 truncate max-w-[220px]">${tags}</span>
      </div>
    `;
  } else if (iocType === 'hash') {
    const mb = metrics?.malwarebazaar || {};
    el.vendor2Icon.textContent = 'MB';
    el.vendor2Title.textContent = 'MalwareBazaar (abuse.ch)';
    el.vendor2Subtitle.textContent = 'Binary Sample Threat Registry';
    el.vendor2StatusPill.textContent = mb.confirmed ? 'CONFIRMED' : 'NO RECORD';

    if (mb.confirmed) {
      el.vendor2StatusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-neon-crimson';
    } else {
      el.vendor2StatusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-transparent text-slate-400 border border-white/[0.08]';
    }

    const sig = mb.signature || 'Unclassified / Generic';
    const ftype = mb.file_type || 'N/A';
    const delivery = mb.delivery_method || 'Unknown';

    el.vendor2Content.innerHTML = `
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Registry Status:</span>
        <span class="font-extrabold ${mb.confirmed ? 'text-rose-400' : 'text-slate-400'}">${mb.confirmed ? 'CONFIRMED MALWARE SAMPLE' : 'NO KNOWN RECORD'}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">Malware Family / Signature:</span>
        <span class="text-slate-200 font-extrabold">${sig}</span>
      </div>
      <div class="flex justify-between py-1.5 border-b border-white/[0.06]">
        <span class="text-slate-400">File Format:</span>
        <span class="text-slate-200 font-semibold">${ftype}</span>
      </div>
      <div class="flex justify-between py-1.5">
        <span class="text-slate-400">Delivery Vector:</span>
        <span class="text-slate-200 font-semibold">${delivery}</span>
      </div>
    `;
  }
}

// Containment Playbook
function renderContainmentPlaybook(actions) {
  el.checklistItems.innerHTML = '';

  if (!actions || actions.length === 0) {
    el.checklistItems.innerHTML = '<div class="text-xs font-mono text-slate-500">No rule-based containment actions required for this benign profile.</div>';
    updateChecklistProgress(0, 0);
    return;
  }

  actions.forEach((action, i) => {
    const item = document.createElement('label');
    item.className = 'flex items-start gap-3 p-3 bg-[#0D111A]/80 hover:bg-[#131926] border border-white/[0.08] hover:border-white/[0.16] rounded-xl cursor-pointer transition-colors backdrop-blur-sm';

    item.innerHTML = `
      <input type="checkbox" class="soc-action-cb mt-0.5 h-4 w-4 rounded bg-[#07090E] border-white/20 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-0" data-idx="${i}" />
      <span class="text-xs font-mono text-slate-300 select-none leading-relaxed flex-1">${action}</span>
    `;

    el.checklistItems.appendChild(item);
  });

  const checkboxes = el.checklistItems.querySelectorAll('.soc-action-cb');
  checkboxes.forEach((cb) => {
    cb.addEventListener('change', () => {
      const checked = el.checklistItems.querySelectorAll('.soc-action-cb:checked').length;
      updateChecklistProgress(checked, checkboxes.length);
    });
  });

  updateChecklistProgress(0, actions.length);
}

function updateChecklistProgress(completed, total) {
  el.checklistProgressText.textContent = `${completed} of ${total} containment actions executed`;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  el.checklistPercent.textContent = `${pct}%`;
}

// Copy Defanged Utility
el.copyDefangedBtn.addEventListener('click', () => {
  const text = el.resultDefangedIoc.textContent.trim();
  if (!text) return;

  navigator.clipboard
    .writeText(text)
    .then(() => {
      el.copyBtnText.textContent = 'COPIED!';
      el.copyDefangedBtn.classList.add('bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/50');
      showToast('DEFANGED IOC COPIED', `[${text}] copied safely to clipboard.`, 'success', 2500);

      setTimeout(() => {
        el.copyBtnText.textContent = 'COPY DEFANGED';
        el.copyDefangedBtn.classList.remove('bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/50');
      }, 2000);
    })
    .catch(() => {
      showToast('COPY FAILED', 'Clipboard permission denied.', 'error');
    });
});

// Export Incident Report
el.downloadReportBtn.addEventListener('click', () => {
  const data = state.lastAnalysis;
  if (!data) return;

  const checkboxes = el.checklistItems.querySelectorAll('.soc-action-cb');
  const actionList = (data.recommended_actions || [])
    .map((action, i) => {
      const isDone = checkboxes[i] && checkboxes[i].checked;
      return `[${isDone ? 'X' : ' '}] Action Item ${i + 1}: ${action}`;
    })
    .join('\n');

  const nowIso = new Date().toISOString();
  const operator = state.currentUser || 'SOC_ANALYST';

  const report = `================================================================================
CIPHERINTEL CYBER COMMAND // TACTICAL INCIDENT ENRICHMENT REPORT
================================================================================
Generated Timestamp   : ${nowIso}
Authorized Operator   : ${operator}
Platform Architecture : In-Memory CipherIntel Multi-Source Enrichment Engine

[1] TARGET INDICATOR DOSSIER
--------------------------------------------------------------------------------
Original Indicator    : ${data.original_ioc}
Defanged Indicator    : ${data.defanged_ioc}
Vector Classification : ${data.ioc_type.toUpperCase()}
Calculated Threat Score: ${data.threat_score} / 100
Assessed Severity     : ${data.severity.toUpperCase()}
Threat Classification : ${data.classification}
Multi-Factor Verdict  : ${data.verdict || 'N/A'}

[2] MULTI-FACTOR WEIGHT CONTRIBUTIONS & TRANSPARENCY
--------------------------------------------------------------------------------
${JSON.stringify(data.score_breakdown || {}, null, 2)}

[3] CORRELATED MITRE ATT&CK ENTERPRISE TECHNIQUES
--------------------------------------------------------------------------------
${(data.mitre_techniques || []).map(t => `* [${t.technique_id}] ${t.technique_name} (${t.tactic})\n  Reason: ${t.reason}`).join('\n\n') || 'None mapped'}

[4] MULTI-SENSOR TELEMETRY FINDINGS
--------------------------------------------------------------------------------
* VirusTotal v3 Aggregation:
  - Malicious Flagged  : ${data.raw_metrics?.virustotal?.malicious || 0} / ${data.raw_metrics?.virustotal?.total || 0} Engines
  - Suspicious Engines : ${data.raw_metrics?.virustotal?.suspicious || 0}
  - Community Rep Score: ${data.raw_metrics?.virustotal?.reputation || 0}
  - Autonomous System  : ${data.raw_metrics?.virustotal?.as_owner || data.raw_metrics?.virustotal?.registrar || 'N/A'}

* Secondary Telemetry Provider:
${JSON.stringify(data.raw_metrics?.[data.ioc_type === 'ip' ? 'abuseipdb' : data.ioc_type === 'hash' ? 'malwarebazaar' : 'urlhaus'] || {}, null, 2)}

[5] SOC CONTAINMENT & REMEDIATION PLAYBOOK STATUS
--------------------------------------------------------------------------------
${actionList || 'No containment actions listed.'}

================================================================================
END OF INCIDENT REPORT // CLASSIFIED SECURITY TELEMETRY
CIPHERINTEL THREAT INTELLIGENCE PLATFORM
================================================================================
`;

  const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
  const downloadUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const safeIoc = (data.defanged_ioc || data.original_ioc).replace(/[^a-zA-Z0-9_-]/g, '_');
  a.href = downloadUrl;
  a.download = `CipherIntel_Incident_${data.ioc_type.toUpperCase()}_${safeIoc}_${Date.now()}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(downloadUrl);

  showToast('INCIDENT REPORT EXPORTED', `Downloaded incident file [${a.download}].`, 'success');
});

// ============================================================================
// Task 3.3: BINARY & STATIC ARTIFACT ANALYSIS CONTROLLER
// ============================================================================

// Drag and drop event listeners
el.artifactDropzone.addEventListener('click', () => {
  el.artifactFileInput.click();
});

el.artifactDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  el.artifactDropzone.classList.add('dropzone-active');
});

el.artifactDropzone.addEventListener('dragleave', (e) => {
  e.preventDefault();
  el.artifactDropzone.classList.remove('dropzone-active');
});

el.artifactDropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  el.artifactDropzone.classList.remove('dropzone-active');
  const files = e.dataTransfer.files;
  if (files && files.length > 0) {
    stageArtifactFile(files[0]);
  }
});

el.artifactFileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files.length > 0) {
    stageArtifactFile(e.target.files[0]);
  }
});

function stageArtifactFile(file) {
  state.currentArtifactFile = file;
  el.artifactStagedFilename.textContent = file.name;
  el.artifactStagedSize.textContent = `${(file.size / 1024).toFixed(1)} KB (${file.size.toLocaleString()} bytes)`;
  el.artifactStagedType.textContent = file.type || 'Binary Stream (PE)';
  el.artifactStagedBar.classList.remove('hidden');

  showToast('ARTIFACT STAGED', `Loaded [${file.name}] into memory enclave.`, 'info');
}

// "Triage Artifact" Button Handler
el.artifactAnalyzeBtn.addEventListener('click', async () => {
  if (!state.currentArtifactFile) {
    showToast('NO ARTIFACT', 'Please select or drag-and-drop a binary file first.', 'warning');
    return;
  }

  el.artifactAnalyzeBtn.disabled = true;
  el.artifactAnalyzeIcon.classList.add('hidden');
  el.artifactAnalyzeSpinner.classList.remove('hidden');
  el.artifactAnalyzeBtnText.textContent = 'ANALYZING...';

  el.artifactResultsSection.classList.add('hidden');
  el.artifactScanningLoader.classList.remove('hidden');
  el.artifactScanningLoader.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const formData = new FormData();
    formData.append('file', state.currentArtifactFile);

    const report = await apiRequest('/api/artifact/analyze', {
      method: 'POST',
      body: formData,
    });

    state.lastArtifactReport = report;
    renderArtifactReport(report);
    showToast('STATIC TRIAGE COMPLETE', `Extracted ${report.sections?.length || 0} sections & evaluated static risk.`, 'success');
  } catch (error) {
    showToast('TRIAGE FAILED', error.message, 'error', 6000);
  } finally {
    el.artifactAnalyzeBtn.disabled = false;
    el.artifactAnalyzeIcon.classList.remove('hidden');
    el.artifactAnalyzeSpinner.classList.add('hidden');
    el.artifactAnalyzeBtnText.textContent = 'TRIAGE ARTIFACT';
    el.artifactScanningLoader.classList.add('hidden');
  }
});

// Render Static Artifact Report
function renderArtifactReport(report) {
  el.artifactResultsSection.classList.remove('hidden');

  // 1. Executive Card Details
  el.artFilenameTitle.textContent = report.filename || 'sample.bin';
  el.artSha256.textContent = report.hashes?.sha256 || 'N/A';
  el.artMachine.textContent = report.headers?.machine || 'x86/x64';
  el.artTimestamp.textContent = report.headers?.compilation_timestamp || 'N/A';
  el.artSubsystem.textContent = report.headers?.subsystem || 'Windows GUI';
  el.artSectionsCount.textContent = `${report.sections?.length || 0} Sections`;

  // PE Badge & Packing Badge
  if (report.is_pe) {
    el.artPeBadge.textContent = 'WINDOWS PE BINARY';
    el.artPeBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30';
  } else {
    el.artPeBadge.textContent = 'RAW / NON-PE BINARY';
    el.artPeBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30';
  }

  const isHighEntropy = (report.overall_entropy >= 7.2) || Boolean(report.is_packed_or_encrypted);
  const packingList = report.packing_indicators || [];

  if (isHighEntropy) {
    el.artPackingBadge.textContent = 'PACKED / ENCRYPTED ARTIFACT';
    el.artPackingBadge.className = 'px-2.5 py-1 rounded text-[10px] font-mono font-extrabold bg-rose-500/25 text-rose-300 border border-rose-500/60 animate-pulse shadow-neon-crimson';
    el.artPackingAlert.className = 'p-4 bg-rose-950/60 border-2 border-rose-500/80 rounded-xl text-xs font-mono text-rose-200 space-y-2 shadow-neon-crimson animate-pulse';
    el.artPackingAlert.classList.remove('hidden');
    el.artPackingAlert.innerHTML = `
      <div class="font-extrabold flex items-center gap-2 text-sm text-rose-300">
        <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
        <span>🚨 CRITICAL ARTIFACT ALERT: PACKED / ENCRYPTED ARTIFACT DETECTED</span>
      </div>
      <p class="text-xs text-rose-300">
        Overall file entropy is measured at <strong class="text-white font-extrabold">${(report.overall_entropy || 0).toFixed(2)} / 8.0</strong> (&ge; 7.2 threshold).
        This strongly indicates the presence of encrypted shellcode, obfuscated packers, or compressed malware payloads.
      </p>
      ${packingList.length > 0 ? `
        <ul id="art-packing-list" class="list-disc list-inside space-y-1 text-[11px] text-rose-400 pt-1.5 border-t border-rose-500/25">
          ${packingList.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
        </ul>
      ` : ''}
    `;
  } else if (packingList.length > 0) {
    el.artPackingBadge.textContent = `PACKED / OBFUSCATED (${packingList.length})`;
    el.artPackingBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-300 border border-rose-500/40 animate-pulse';
    el.artPackingAlert.className = 'p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs font-mono text-rose-300 space-y-1';
    el.artPackingAlert.classList.remove('hidden');
    el.artPackingAlert.innerHTML = `
      <div class="font-bold flex items-center gap-1.5">
        <span>🚨 POTENTIAL PACKER / ENCRYPTION SIGNATURES DETECTED:</span>
      </div>
      <ul id="art-packing-list" class="list-disc list-inside space-y-0.5 text-[11px] text-rose-400">
        ${packingList.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
      </ul>
    `;
  } else {
    el.artPackingBadge.textContent = 'PACKING: CLEAN';
    el.artPackingBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    el.artPackingAlert.classList.add('hidden');
  }

  // Static Risk Score & Verdict
  const score = report.static_risk_score || 0;
  el.artStaticScore.textContent = `${score.toFixed(1)} / 100`;
  const verdict = report.verdict || 'Low';
  el.artStaticVerdictBadge.textContent = `${verdict.toUpperCase()} STATIC RISK`;

  if (verdict === 'Critical' || verdict === 'High') {
    el.artStaticVerdictBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-extrabold uppercase border bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-neon-crimson';
    el.artStaticScore.className = 'text-2xl font-extrabold font-mono text-rose-400';
  } else if (verdict === 'Medium') {
    el.artStaticVerdictBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-extrabold uppercase border bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-neon-amber';
    el.artStaticScore.className = 'text-2xl font-extrabold font-mono text-amber-400';
  } else {
    el.artStaticVerdictBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-extrabold uppercase border bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-neon-emerald';
    el.artStaticScore.className = 'text-2xl font-extrabold font-mono text-emerald-400';
  }

  // 2. Section Entropy Visualizer
  const entVal = Number(report.overall_entropy || 0);
  el.artOverallEntropy.textContent = `${entVal.toFixed(2)} / 8.0`;
  if (entVal >= 7.2) {
    el.artOverallEntropy.className = 'font-extrabold text-rose-400 ml-1 animate-pulse';
  } else if (entVal >= 6.0) {
    el.artOverallEntropy.className = 'font-bold text-amber-400 ml-1';
  } else {
    el.artOverallEntropy.className = 'font-bold text-indigo-400 ml-1';
  }
  renderSectionsEntropy(report.sections || [], entVal);

  // 3. IAT & Flagged APIs
  renderFlaggedApis(report.flagged_apis || [], report.imported_dlls_summary || {});

  // 4. Extracted Strings & IOCs with "Pivot to Lookup"
  renderExtractedIocs(report.extracted_iocs || {}, report.total_strings_extracted || 0);

  // 5. Baseline YARA Matches (if any)
  renderBaselineYaraResults(report.yara_matches || []);

  el.artifactResultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Section Entropy Cards Renderer
function renderSectionsEntropy(sections, overallEntropy = 0) {
  el.artSectionsContainer.innerHTML = '';

  if (!sections || sections.length === 0) {
    if (overallEntropy >= 7.2) {
      el.artSectionsContainer.innerHTML = `
        <div class="col-span-full p-4 bg-rose-950/40 border-2 border-rose-500/60 rounded-xl space-y-2.5 shadow-neon-crimson">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-sm text-white">RAW BINARY / SHELLCODE BUFFER</span>
              <span class="px-2 py-0.5 rounded text-[9px] font-mono font-extrabold bg-rose-500/30 text-rose-300 border border-rose-500/50 animate-pulse">
                [HIGH ENTROPY &ge; 7.2: PACKED / ENCRYPTED]
              </span>
            </div>
            <div class="text-xs font-mono">
              <span class="text-slate-400">Entropy:</span>
              <span class="text-rose-400 font-extrabold ml-1">${overallEntropy.toFixed(2)} / 8.0</span>
            </div>
          </div>
          <div class="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-rose-500/30">
            <div class="h-full bg-rose-500 transition-all duration-700" style="width: ${Math.min(100, (overallEntropy / 8.0) * 100).toFixed(1)}%"></div>
          </div>
          <p class="text-[11px] font-mono text-slate-300">
            Non-PE artifact exhibits near-maximal Shannon entropy with zero standard PE section headers, strongly indicating raw encrypted shellcode, high-entropy packing, or cryptographic payload.
          </p>
        </div>
      `;
    } else {
      el.artSectionsContainer.innerHTML = `
        <div class="col-span-full p-4 border border-dashed border-white/[0.08] rounded-xl text-center font-mono text-xs text-slate-400">
          NO PE SECTIONS DETECTED (RAW DATA / TEXT SCRIPT &bull; ENTROPY: ${overallEntropy.toFixed(2)} / 8.0)
        </div>
      `;
    }
    return;
  }

  sections.forEach((sec) => {
    const card = document.createElement('div');
    const isPacked = sec.is_high_entropy || sec.entropy > 7.0;

    let barColor = 'bg-emerald-400';
    let borderColor = 'border-white/[0.08] hover:border-white/[0.16]';
    let entropyTextClass = 'text-emerald-400';

    if (sec.entropy > 7.0) {
      barColor = 'bg-rose-500';
      borderColor = 'border-rose-500/40 shadow-neon-crimson';
      entropyTextClass = 'text-rose-400 font-extrabold';
    } else if (sec.entropy >= 6.0) {
      barColor = 'bg-amber-400';
      borderColor = 'border-amber-500/30';
      entropyTextClass = 'text-amber-400';
    }

    const entropyPct = Math.min(100, Math.max(0, (sec.entropy / 8.0) * 100));

    card.className = `p-3.5 bg-[#0D111A]/80 border ${borderColor} rounded-xl space-y-2.5 transition-all`;

    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <span class="font-bold font-mono text-sm text-white">${sec.name}</span>
          ${isPacked ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-mono font-extrabold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">[PACKED &gt; 7.0]</span>' : ''}
        </div>
        <div class="text-xs font-mono">
          <span class="text-slate-400">Entropy:</span>
          <span class="${entropyTextClass} ml-1">${sec.entropy.toFixed(2)} / 8.0</span>
        </div>
      </div>

      <!-- Entropy Progress Bar -->
      <div class="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-white/[0.08]">
        <div class="h-full ${barColor} transition-all duration-700" style="width: ${entropyPct}%"></div>
      </div>

      <!-- Raw vs Virtual Size Comparison -->
      <div class="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-1 border-t border-white/[0.06]">
        <div>
          <span class="text-slate-500">Raw Size:</span>
          <span class="text-slate-200 font-bold ml-1">${(sec.raw_size || 0).toLocaleString()} B</span>
        </div>
        <div>
          <span class="text-slate-500">Virtual Size:</span>
          <span class="text-slate-200 font-bold ml-1">${(sec.virtual_size || 0).toLocaleString()} B</span>
        </div>
        <div class="col-span-2 text-[10px] text-slate-500 flex justify-between">
          <span>Discrepancy: ${(sec.size_discrepancy || 0).toLocaleString()} B</span>
          <span>Ratio: ${sec.discrepancy_ratio || 0}x</span>
        </div>
      </div>
    `;

    el.artSectionsContainer.appendChild(card);
  });
}

// IAT & Flagged APIs Renderer
function renderFlaggedApis(flaggedApis, dllSummary) {
  el.artFlaggedApisContainer.innerHTML = '';
  el.artFlaggedApisCount.textContent = `${flaggedApis.length} ${flaggedApis.length === 1 ? 'FLAGGED API' : 'FLAGGED APIS'}`;

  if (!flaggedApis || flaggedApis.length === 0) {
    el.artFlaggedApisContainer.innerHTML = `
      <div class="p-3 border border-dashed border-white/[0.08] rounded-xl text-center font-mono text-xs text-slate-400">
        NO HIGH-RISK INJECTION OR EVASION APIS DETECTED IN IMPORT TABLE
      </div>
    `;
  } else {
    flaggedApis.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'p-3 bg-[#0D111A]/80 hover:bg-[#131926] border border-white/[0.08] hover:border-white/[0.16] rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 transition-colors font-mono text-xs';

      const mitreObj = item.mitre_technique;
      const mitreTag = mitreObj
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">[${mitreObj.technique_id} ${mitreObj.technique_name}]</span>`
        : '';

      let catBadgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      if (item.category.includes('Memory') || item.category.includes('Injection')) {
        catBadgeColor = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
      }

      row.innerHTML = `
        <div class="flex items-center gap-2 flex-wrap">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${catBadgeColor}">
            ${item.category}
          </span>
          <span class="font-semibold text-white text-sm">${item.api_name}</span>
          <span class="text-slate-500">(${item.dll})</span>
        </div>
        <div>
          ${mitreTag}
        </div>
      `;

      el.artFlaggedApisContainer.appendChild(row);
    });
  }

  // DLL Summary
  el.artDllsList.innerHTML = '';
  const dllEntries = Object.entries(dllSummary || {});
  if (dllEntries.length === 0) {
    el.artDllsList.innerHTML = '<span class="text-slate-500">No imported DLL entries cataloged.</span>';
  } else {
    dllEntries.forEach(([dll, count]) => {
      const chip = document.createElement('span');
      chip.className = 'px-2 py-1 bg-[#0D111A]/80 border border-white/[0.08] rounded-lg text-slate-300 text-[11px]';
      chip.textContent = `${dll} (${count} functions)`;
      el.artDllsList.appendChild(chip);
    });
  }
}

// Extracted IOCs & "Pivot to Lookup" Renderer
function renderExtractedIocs(extracted, totalCount) {
  el.artExtractedIocsContainer.innerHTML = '';
  const ips = extracted.ips || [];
  const domains = extracted.domains || [];
  const urls = extracted.urls || [];
  const total = ips.length + domains.length + urls.length;

  el.artExtractedIocsCount.textContent = `${total} INDICATORS (${totalCount} STRINGS SEARCHED)`;

  if (total === 0) {
    el.artExtractedIocsContainer.innerHTML = `
      <div class="p-3 border border-dashed border-white/[0.08] rounded-xl text-center text-slate-400 font-mono text-xs">
        NO EMBEDDED PUBLIC IPV4, DOMAIN, OR URL PATTERNS DISCOVERED IN ARTIFACT STRINGS
      </div>
    `;
    return;
  }

  function createIocGroup(title, items, type) {
    if (!items || items.length === 0) return null;
    const groupDiv = document.createElement('div');
    groupDiv.className = 'space-y-1.5';

    groupDiv.innerHTML = `
      <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
        <span class="text-indigo-400">⚡</span> ${title} (${items.length}):
      </div>
    `;

    const listDiv = document.createElement('div');
    listDiv.className = 'space-y-1.5';

    items.forEach((val) => {
      const row = document.createElement('div');
      row.className = 'p-2.5 bg-[#0D111A]/80 hover:bg-[#131926] border border-white/[0.08] hover:border-white/[0.16] rounded-xl flex items-center justify-between gap-3 transition-colors';

      row.innerHTML = `
        <span class="text-xs font-mono text-slate-200 truncate max-w-md select-all font-semibold">${val}</span>
        <button
          type="button"
          class="pivot-btn px-3 py-1 bg-indigo-500/15 hover:bg-indigo-600 text-indigo-300 hover:text-white font-semibold font-mono text-[10px] uppercase rounded-lg border border-indigo-500/30 transition-all flex items-center gap-1 shadow-sm active:scale-95 whitespace-nowrap"
          data-type="${type}"
          data-val="${val}"
          title="Switch tab & look up this indicator in IOC Telemetry"
        >
          <span>⚡ PIVOT TO LOOKUP</span>
        </button>
      `;

      listDiv.appendChild(row);
    });

    groupDiv.appendChild(listDiv);
    return groupDiv;
  }

  const ipGroup = createIocGroup('Discovered IPv4 Addresses', ips, 'ip');
  if (ipGroup) el.artExtractedIocsContainer.appendChild(ipGroup);

  const domainGroup = createIocGroup('Discovered Domain Names (FQDN)', domains, 'domain');
  if (domainGroup) el.artExtractedIocsContainer.appendChild(domainGroup);

  const urlGroup = createIocGroup('Discovered URLs & Paths', urls, 'url');
  if (urlGroup) el.artExtractedIocsContainer.appendChild(urlGroup);

  // Attach event listener for all Pivot Buttons
  const pivotButtons = el.artExtractedIocsContainer.querySelectorAll('.pivot-btn');
  pivotButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-type');
      const val = btn.getAttribute('data-val');
      pivotToIoc(val, type);
    });
  });
}

// "Pivot to Lookup" Handler: Switches tabs and runs analysis directly!
function pivotToIoc(iocString, iocType) {
  // 1. Switch to IOC module
  switchModule('ioc');

  // 2. Select appropriate pillar
  if (iocType && PILLAR_CONFIG[iocType]) {
    switchPillar(iocType);
  }

  // 3. Put into search input
  el.iocInput.value = iocString;
  handleIocInputDetection();

  // 4. Fire analysis scan
  showToast('PIVOTING TO IOC', `Initiating live dual-feed investigation for [${iocString}].`, 'info');
  runAnalysis(iocString);
}

// Baseline YARA Results Renderer
function renderBaselineYaraResults(matches) {
  if (!matches || matches.length === 0) return;

  const baselineDiv = document.createElement('div');
  baselineDiv.className = 'p-4 bg-[#0D111A]/80 border border-violet-500/30 rounded-xl space-y-2 font-mono text-xs';

  baselineDiv.innerHTML = `
    <div class="flex items-center gap-2 text-violet-300 font-bold uppercase text-[11px]">
      <span>🛡️ BASELINE YARA SIGNATURE MATCHES (${matches.length}):</span>
    </div>
    <div class="space-y-1.5">
      ${matches.map(m => `
        <div class="p-2 bg-[#07090E]/60 rounded-lg border border-violet-500/20 flex items-center justify-between">
          <span class="font-bold text-white">${m.rule_name}</span>
          <span class="text-[10px] text-violet-300">${m.meta?.description || 'Packer / Payload signature'}</span>
        </div>
      `).join('')}
    </div>
  `;

  el.artResultsSection.appendChild(baselineDiv);
}

// ============================================================================
// CUSTOM YARA STUDIO EXECUTION CONTROLLER
// ============================================================================
const YARA_PRESETS = {
  upx: `rule UPX_Packer_Rule {
    meta:
        description = "Detects UPX packed executable headers"
        threat_level = "Medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        2 of them
}`,
  injection: `rule Injection_APIs_Rule {
    meta:
        description = "Detects process memory injection primitives"
        threat_level = "High"
    strings:
        $valloc = "VirtualAllocEx" ascii nocase
        $wpm = "WriteProcessMemory" ascii nocase
        $crt = "CreateRemoteThread" ascii nocase
    condition:
        2 of them
}`,
  powershell: `rule PowerShell_Cradle_Rule {
    meta:
        description = "Detects PowerShell execution or download cradle"
        threat_level = "High"
    strings:
        $ps = "powershell" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $down = "DownloadFile" ascii nocase
        $down2 = "DownloadString" ascii nocase
    condition:
        $ps and any of ($hidden, $down, $down2)
}`,
};

el.yaraPresetUpx.addEventListener('click', () => {
  el.yaraRuleEditor.value = YARA_PRESETS.upx;
  showToast('PRESET LOADED', 'Loaded UPX Packer detection rule.', 'info', 2000);
});

el.yaraPresetInjection.addEventListener('click', () => {
  el.yaraRuleEditor.value = YARA_PRESETS.injection;
  showToast('PRESET LOADED', 'Loaded Process Injection detection rule.', 'info', 2000);
});

el.yaraPresetPowershell.addEventListener('click', () => {
  el.yaraRuleEditor.value = YARA_PRESETS.powershell;
  showToast('PRESET LOADED', 'Loaded PowerShell Cradle detection rule.', 'info', 2000);
});

// Execute Custom YARA Rule
el.yaraExecuteBtn.addEventListener('click', async () => {
  if (!state.currentArtifactFile) {
    showToast('NO ARTIFACT', 'Please stage a binary file to test YARA rules against.', 'warning');
    return;
  }

  const ruleCode = el.yaraRuleEditor.value.trim();
  if (!ruleCode) {
    showToast('EMPTY RULE', 'Please enter a valid YARA rule string.', 'warning');
    return;
  }

  el.yaraExecuteBtn.disabled = true;
  el.yaraBtnIcon.classList.add('hidden');
  el.yaraSpinner.classList.remove('hidden');
  el.yaraBtnText.textContent = 'COMPILING & EVALUATING...';

  try {
    const formData = new FormData();
    formData.append('file', state.currentArtifactFile);
    formData.append('rule', ruleCode);

    const result = await apiRequest('/api/artifact/yara-test', {
      method: 'POST',
      body: formData,
    });

    renderYaraStudioResults(result);

    if (result.success) {
      if (result.match_count > 0) {
        showToast('YARA MATCH', `Rule matched ${result.match_count} signature pattern(s)!`, 'success');
      } else {
        showToast('NO MATCH', 'Rule compiled cleanly but found 0 matches in binary.', 'info');
      }
    } else {
      showToast('YARA ERROR', result.error || 'Compilation syntax error.', 'error', 6000);
    }
  } catch (error) {
    showToast('EVALUATION FAILED', error.message, 'error', 6000);
  } finally {
    el.yaraExecuteBtn.disabled = false;
    el.yaraBtnIcon.classList.remove('hidden');
    el.yaraSpinner.classList.add('hidden');
    el.yaraBtnText.textContent = 'EVALUATE YARA RULE';
  }
});

function renderYaraStudioResults(result) {
  el.yaraResultsContainer.innerHTML = '';

  if (!result.success) {
    el.yaraResultsContainer.innerHTML = `
      <div class="p-3.5 bg-rose-500/15 border border-rose-500/40 rounded-xl text-rose-300 font-mono text-xs space-y-1 animate-enter">
        <div class="font-extrabold flex items-center gap-1.5 text-rose-400">
          <span>❌ YARA COMPILATION SYNTAX ERROR:</span>
        </div>
        <div class="text-[11px] font-mono text-rose-200 bg-slate-950/70 p-2.5 rounded-lg border border-rose-500/20 overflow-x-auto">
          ${result.error || 'Unknown syntax error during rule compilation.'}
        </div>
      </div>
    `;
    return;
  }

  if (result.match_count === 0) {
    el.yaraResultsContainer.innerHTML = `
      <div class="p-3.5 bg-[#0D111A]/80 border border-white/[0.08] rounded-xl text-slate-400 font-mono text-xs text-center animate-enter">
        ✓ RULE COMPILED CLEANLY &bull; 0 MATCHES FOUND IN UPLOADED ARTIFACT
      </div>
    `;
    return;
  }

  // Render Matches
  const matchesDiv = document.createElement('div');
  matchesDiv.className = 'space-y-2.5 animate-enter';

  result.matches.forEach((m) => {
    const card = document.createElement('div');
    card.className = 'p-3.5 bg-[#0D111A]/80 border border-emerald-500/30 rounded-xl space-y-2.5 font-mono text-xs';

    const stringsList = (m.strings || []).map((s) => `
      <div class="p-2 bg-[#07090E]/60 border border-white/[0.08] rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px]">
        <div class="flex items-center gap-2">
          <span class="text-indigo-400 font-semibold">${s.identifier || '$string'}</span>
          <span class="text-slate-400">Offset: 0x${s.offset.toString(16).toUpperCase()} (${s.offset})</span>
        </div>
        <div class="text-slate-200 truncate max-w-sm font-semibold">
          "${s.data_preview || ''}"
        </div>
      </div>
    `).join('');

    card.innerHTML = `
      <div class="flex items-center justify-between pb-2 border-b border-white/[0.06]">
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
            MATCHED
          </span>
          <span class="font-semibold text-white text-sm">${m.rule_name}</span>
        </div>
        <span class="text-[10px] text-slate-400">
          ${(m.strings || []).length} string occurrences
        </span>
      </div>

      ${m.meta && Object.keys(m.meta).length > 0 ? `
        <div class="text-[10px] text-slate-400 flex flex-wrap gap-3">
          ${Object.entries(m.meta).map(([k, v]) => `<span><strong class="text-slate-300">${k}:</strong> ${v}</span>`).join('')}
        </div>
      ` : ''}

      <div class="space-y-1">
        <div class="text-[10px] font-bold text-slate-400 uppercase">Matched Offsets &amp; String Previews:</div>
        ${stringsList || '<span class="text-slate-500">Condition evaluated to true (Boolean logic).</span>'}
      </div>
    `;

    matchesDiv.appendChild(card);
  });

  el.yaraResultsContainer.appendChild(matchesDiv);
}

// Boot Application
document.addEventListener('DOMContentLoaded', () => {
  initCyberMeshCanvas();
  initializeApp();
});
