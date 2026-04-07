// Datum Gateway UI — Client-side app logic

const APP_STATE = {
  view: 'login',
  authCode: null,
  sessionToken: null,
  agents: [],
  auditLog: [],
  credentials: [],
  pollInterval: null,
};

// ===== Init =====

document.addEventListener('DOMContentLoaded', () => {
  const token = sessionStorage.getItem('datum-session-token');
  if (token) {
    APP_STATE.sessionToken = token;
    renderDashboard().catch(err => {
      // Stale token — clear and show login
      sessionStorage.removeItem('datum-session-token');
      APP_STATE.sessionToken = null;
      renderLogin();
    });
  } else {
    renderLogin();
  }
});

// ===== Base64url helpers for WebAuthn =====

function b64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
}

function prepareGetOptions(opts) {
  opts.challenge = fromB64url(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({
      ...c, id: fromB64url(c.id),
    }));
  }
  return opts;
}

function prepareCreateOptions(opts) {
  opts.challenge = fromB64url(opts.challenge);
  opts.user.id = fromB64url(opts.user.id);
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map(c => ({
      ...c, id: fromB64url(c.id),
    }));
  }
  return opts;
}

function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON:    b64url(cred.response.clientDataJSON),
      authenticatorData: b64url(cred.response.authenticatorData),
      signature:         b64url(cred.response.signature),
      userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : null,
    },
  };
}

function serializeAttestation(cred) {
  return {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON:    b64url(cred.response.clientDataJSON),
      attestationObject: b64url(cred.response.attestationObject),
    },
  };
}

// ===== Login View =====

function renderLogin() {
  APP_STATE.view = 'login';
  document.getElementById('app').innerHTML = `
    <div class="login-container">
      <div class="login-card">
        <div class="login-header">
          <div class="login-logo">${DATUM_LOGO_SVG}</div>
          <h1 class="login-title">Datum</h1>
          <p class="login-subtitle">Multi-agent intelligence</p>
        </div>

        <div class="totp-input">
          <div class="input-field">
            <label for="totp-code">Authenticator Code</label>
            <input
              id="totp-code"
              type="text"
              inputmode="numeric"
              placeholder="000000"
              maxlength="6"
              autocomplete="one-time-code"
              onkeydown="if(event.key==='Enter') handleTOTPSubmit()"
            />
          </div>
          <button class="btn btn-accent" onclick="handleTOTPSubmit()">
            <i class="ph ph-arrow-right"></i> Sign In
          </button>
          <p id="totp-error" style="margin-top:10px;font-size:13px;text-align:center;color:var(--danger);min-height:18px;"></p>
        </div>
      </div>
    </div>
  `;
  document.getElementById('totp-code').focus();
}

function renderTOTP() {
  APP_STATE.view = 'totp';
  document.getElementById('app').innerHTML = `
    <div class="login-container">
      <div class="login-card">
        <div class="login-header">
          <div class="login-logo">${DATUM_LOGO_SVG}</div>
          <h1 class="login-title">Datum</h1>
          <p class="login-subtitle">Multi-agent intelligence</p>
        </div>

        <div class="totp-input">
          <div class="input-field">
            <label for="totp-code">Authenticator Code</label>
            <input
              id="totp-code"
              type="text"
              placeholder="000000"
              maxlength="6"
              pattern="[0-9]{6}"
              inputmode="numeric"
              onkeypress="event.key === 'Enter' && handleTOTPSubmit()"
            />
          </div>
          <button class="btn btn-accent" onclick="handleTOTPSubmit()">
            <i class="ph ph-check"></i> Verify Code
          </button>
          <button class="btn-link" onclick="renderLogin()">Back</button>
        </div>
      </div>
    </div>
  `;
  document.getElementById('totp-code').focus();
}

async function handleEmailAuth() {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'email' }),
    });
    const data = await res.json();
    APP_STATE.authCode = data.auth_code;
    renderAuthWait('email');
  } catch (err) {
    console.error('Email auth failed:', err);
    alert('Email auth failed. Try TOTP instead.');
  }
}

async function handlePasskeyLogin() {
  try {
    const startRes = await fetch('/api/auth/webauthn/auth/start', { method: 'POST' });
    if (!startRes.ok) { renderTOTP(); return; }
    const opts = await startRes.json();
    const credential = await navigator.credentials.get({
      publicKey: prepareGetOptions(opts),
    });
    const finishRes = await fetch('/api/auth/webauthn/auth/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ response: serializeAssertion(credential) }),
    });
    if (finishRes.ok) {
      const data = await finishRes.json();
      APP_STATE.sessionToken = data.token;
      sessionStorage.setItem('datum-session-token', data.token);
      renderDashboard();
    } else {
      alert('Security key authentication failed.');
    }
  } catch (err) {
    console.warn('Passkey login failed:', err);
    if (err.name !== 'NotAllowedError') alert('Security key error: ' + err.message);
  }
}

async function handleTOTPSubmit() {
  const code = document.getElementById('totp-code').value.trim();
  if (!code || code.length !== 6) {
    setTOTPError('Enter a 6-digit code.');
    return;
  }
  setTOTPError('Verifying…');
  try {
    const res = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp: code }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      APP_STATE.sessionToken = data.token;
      sessionStorage.setItem('datum-session-token', data.token);
      await renderDashboard();
    } else {
      setTOTPError(data.error || 'Invalid code. Try again.');
    }
  } catch (err) {
    setTOTPError('Network error: ' + err.message);
  }
}

function setTOTPError(msg) {
  const el = document.getElementById('totp-error');
  if (!el) return;
  el.style.color = msg === 'Verifying…' ? 'var(--text-mid)' : 'var(--danger)';
  el.textContent = msg;
}

function renderAuthWait(method) {
  document.getElementById('app').innerHTML = `
    <div class="login-container">
      <div class="login-card">
        <div class="login-header">
          <div class="login-logo">${DATUM_LOGO_SVG}</div>
          <h1 class="login-title">Datum</h1>
          <p class="login-subtitle">Multi-agent intelligence</p>
        </div>

        <div class="auth-wait">
          <div class="spinner"></div>
          <p class="auth-message">
            ${method === 'email'
              ? 'Check your email — approve the request to continue.'
              : 'Waiting for approval...'}
          </p>
        </div>

        <div class="fallback-link">
          <button class="btn-link" onclick="renderLogin()">Cancel</button>
        </div>
      </div>
    </div>
  `;

  clearInterval(APP_STATE.pollInterval);
  APP_STATE.pollInterval = setInterval(async () => {
    try {
      const res = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: APP_STATE.authCode }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.token) {
          APP_STATE.sessionToken = data.token;
          sessionStorage.setItem('datum-session-token', data.token);
          clearInterval(APP_STATE.pollInterval);
          renderDashboard();
        }
      }
    } catch (err) {
      console.error('Poll error:', err);
    }
  }, 2000);
}

// ===== Dashboard View =====

async function renderDashboard() {
  APP_STATE.view = 'dashboard';

  const authHeader = { 'Authorization': `Bearer ${APP_STATE.sessionToken}` };

  const [agentsRes, auditRes, credsRes] = await Promise.allSettled([
    fetch('/api/agents',                           { headers: authHeader }),
    fetch('/api/audit?limit=20',                   { headers: authHeader }),
    fetch('/api/auth/webauthn/credentials',        { headers: authHeader }),
  ]);

  if (agentsRes.status === 'fulfilled' && agentsRes.value.ok) {
    const d = await agentsRes.value.json();
    APP_STATE.agents = d.agents ?? d ?? [];
  }
  if (auditRes.status === 'fulfilled' && auditRes.value.ok) {
    const d = await auditRes.value.json();
    APP_STATE.auditLog = d.entries ?? d ?? [];
  }
  if (credsRes.status === 'fulfilled' && credsRes.value.ok) {
    const d = await credsRes.value.json();
    APP_STATE.credentials = d.credentials ?? [];
  }

  document.getElementById('app').innerHTML = `
    <div class="dashboard">
      <div class="dashboard-header">
        <div class="header-logo">
          ${DATUM_LOGO_SVG}
          <span>Datum</span>
        </div>
        <div class="header-actions">
          <button class="btn btn-secondary" onclick="handleLogout()">
            <i class="ph ph-sign-out"></i> Logout
          </button>
        </div>
      </div>

      <div class="dashboard-content">
        <!-- Agents Panel -->
        <div class="panel">
          <div class="panel-header">
            <i class="ph ph-robot" style="font-size:16px;vertical-align:-2px;"></i> Agents
          </div>
          <div class="panel-body">
            ${APP_STATE.agents.length > 0
              ? APP_STATE.agents.map(a => `
                  <div class="agent-item" onclick="selectAgent('${a.id}')">
                    <div class="agent-name">${a.name ?? a.id}</div>
                    <div class="agent-status">${a.status || 'ready'}</div>
                  </div>
                `).join('')
              : '<div class="empty-state"><div class="empty-state-text">No agents available</div></div>'}
          </div>
        </div>

        <!-- Audit Log Panel -->
        <div class="panel">
          <div class="panel-header">
            <i class="ph ph-list" style="font-size:16px;vertical-align:-2px;"></i> Audit Log
          </div>
          <div class="panel-body">
            ${APP_STATE.auditLog.length > 0
              ? APP_STATE.auditLog.map(e => `
                  <div class="audit-entry">
                    <div class="audit-time">${new Date(e.timestamp).toLocaleTimeString()}</div>
                    <div class="audit-action">${e.action}</div>
                    <div class="audit-status ${e.status === 'error' ? 'error' : ''}">${e.status || 'ok'}</div>
                  </div>
                `).join('')
              : '<div class="empty-state"><div class="empty-state-text">No events yet</div></div>'}
          </div>
        </div>

        <!-- Security Keys Panel -->
        <div class="panel" style="grid-column: 1 / -1;" id="security-panel">
          <div class="panel-header" style="display:flex;align-items:center;justify-content:space-between;">
            <span><i class="ph ph-key" style="font-size:16px;vertical-align:-2px;"></i> Security Keys</span>
            <button class="btn btn-accent" style="padding:6px 12px;font-size:12px;" onclick="registerPasskey()">
              <i class="ph ph-plus"></i> Register Key
            </button>
          </div>
          <div class="panel-body" id="creds-list">
            ${renderCredsList()}
          </div>
        </div>

        <!-- Terminal Panel -->
        <div class="panel" style="grid-column: 1 / -1;">
          <div class="panel-header">
            <i class="ph ph-terminal" style="font-size:16px;vertical-align:-2px;"></i> Dispatch
          </div>
          <div class="terminal" id="terminal">
            <div class="terminal-line">
              <span class="terminal-prompt">$</span>
              <span class="terminal-input">./datum-gateway --version</span>
            </div>
            <div class="terminal-line">
              <span class="terminal-output">Datum Gateway 1.0 • Ready for dispatch</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  clearInterval(APP_STATE.pollInterval);
  APP_STATE.pollInterval = setInterval(refreshDashboard, 5000);
}

function renderCredsList() {
  if (APP_STATE.credentials.length === 0) {
    return `<div class="empty-state"><div class="empty-state-text">No security keys registered. Click "Register Key" to add your YubiKey.</div></div>`;
  }
  return APP_STATE.credentials.map(c => `
    <div class="agent-item" style="display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div class="agent-name"><i class="ph ph-usb" style="vertical-align:-1px;"></i> ${c.name ?? 'Security Key'}</div>
        <div class="agent-status">${c.deviceType ?? ''} ${c.backedUp ? '· backed up' : ''}</div>
      </div>
      <button class="btn btn-secondary" style="padding:4px 10px;font-size:12px;" onclick="deletePasskey('${c.credentialId}')">
        <i class="ph ph-trash"></i>
      </button>
    </div>
  `).join('');
}

async function registerPasskey() {
  try {
    const startRes = await fetch('/api/auth/webauthn/register/start', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${APP_STATE.sessionToken}` },
    });
    if (!startRes.ok) { alert('Could not start registration.'); return; }

    const opts = await startRes.json();
    const name = prompt('Name this key (e.g. "YubiKey 5C"):', 'YubiKey');
    if (!name) return;

    const credential = await navigator.credentials.create({
      publicKey: prepareCreateOptions(opts),
    });

    const finishRes = await fetch('/api/auth/webauthn/register/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${APP_STATE.sessionToken}`,
      },
      body: JSON.stringify({
        response: serializeAttestation(credential),
        deviceName: name,
      }),
    });

    if (finishRes.ok) {
      terminalLog('Security key registered: ' + name);
      // Refresh creds list
      const credsRes = await fetch('/api/auth/webauthn/credentials', {
        headers: { 'Authorization': `Bearer ${APP_STATE.sessionToken}` },
      });
      if (credsRes.ok) {
        const d = await credsRes.json();
        APP_STATE.credentials = d.credentials ?? [];
        const list = document.getElementById('creds-list');
        if (list) list.innerHTML = renderCredsList();
      }
    } else {
      const err = await finishRes.json();
      alert('Registration failed: ' + (err.error ?? 'Unknown error'));
    }
  } catch (err) {
    if (err.name !== 'NotAllowedError') {
      console.error('Registration error:', err);
      alert('Registration failed: ' + err.message);
    }
  }
}

async function deletePasskey(credentialId) {
  if (!confirm('Remove this security key?')) return;
  try {
    const res = await fetch(`/api/auth/webauthn/credentials/${credentialId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${APP_STATE.sessionToken}` },
    });
    if (res.ok) {
      APP_STATE.credentials = APP_STATE.credentials.filter(c => c.credentialId !== credentialId);
      const list = document.getElementById('creds-list');
      if (list) list.innerHTML = renderCredsList();
      terminalLog('Security key removed.');
    }
  } catch (err) {
    console.error('Delete error:', err);
  }
}

async function refreshDashboard() {
  try {
    const res = await fetch('/api/agents', {
      headers: { 'Authorization': `Bearer ${APP_STATE.sessionToken}` },
    });
    if (res.ok) {
      const d = await res.json();
      APP_STATE.agents = d.agents ?? d ?? [];
    }
  } catch (err) {
    console.error('Refresh error:', err);
  }
}

function selectAgent(id) {
  const agent = APP_STATE.agents.find(a => a.id === id);
  if (agent) terminalLog(`dispatch agent ${agent.name ?? id}`);
}

function terminalLog(msg) {
  const term = document.getElementById('terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className = 'terminal-line';
  line.innerHTML = `<span class="terminal-prompt">$</span><span class="terminal-input"> ${msg}</span>`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function handleLogout() {
  clearInterval(APP_STATE.pollInterval);
  sessionStorage.removeItem('datum-session-token');
  APP_STATE.sessionToken = null;
  renderLogin();
}

// ===== Datum Logo SVG =====

const DATUM_LOGO_SVG = `
  <svg viewBox="0 0 216 216" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Datum">
    <g transform="translate(108 108)">
      <circle cx="0" cy="0" r="90" fill="none" stroke="currentColor" stroke-width="2.5"/>
      <ellipse cx="0" cy="0" rx="55" ry="90" fill="none" stroke="currentColor" stroke-width="2" opacity="0.55"/>
      <ellipse cx="0" cy="0" rx="22" ry="90" fill="none" stroke="currentColor" stroke-width="1.6" opacity="0.4"/>
      <line x1="-90" y1="0" x2="-14" y2="0" stroke="currentColor" stroke-width="1.3" opacity="0.4"/>
      <line x1="14" y1="0" x2="90" y2="0" stroke="currentColor" stroke-width="1.3" opacity="0.4"/>
      <circle cx="0" cy="0" r="5.5" fill="currentColor"/>
      <line x1="0" y1="-90" x2="0" y2="-108" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="0" y1="90" x2="0" y2="108" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="-90" y1="0" x2="-108" y2="0" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="90" y1="0" x2="108" y2="0" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
    </g>
  </svg>
`;
