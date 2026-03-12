/**
 * msauth.js - Microsoft Authentication for LegacyLauncher
 */

const https = require('https');
const path = require('path');
const fs = require('fs');

const MS_CLIENT_ID = '00000000402b5328';
const REDIRECT_URI = 'https://login.live.com/oauth20_desktop.srf';

const AUTH_URL =
  `https://login.live.com/oauth20_authorize.srf` +
  `?client_id=${MS_CLIENT_ID}` +
  `&response_type=code` +
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
  `&scope=XboxLive.signin%20offline_access`;

const AUTH_FILE = path.join(
  process.env.APPDATA || process.env.HOME || '.',
  'LegacyLauncher',
  'auth.json'
);

// ── Helpers ──────────────────────────────────────────────────────────────────

function httpsPost(url, data) {
  return new Promise((resolve, reject) => {
    const isForm = url.includes('login.live');
    const body = isForm
      ? new URLSearchParams(data).toString()
      : JSON.stringify(data);

    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': isForm ? 'application/x-www-form-urlencoded' : 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Accept': 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve(raw); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function httpsGet(url, token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve(raw); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function saveAuth(data) {
  const dir = path.dirname(AUTH_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2));
}

function loadAuth() {
  try {
    if (fs.existsSync(AUTH_FILE)) return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  } catch { /* ignore */ }
  return null;
}

function clearAuth() {
  try { fs.unlinkSync(AUTH_FILE); } catch { /* ignore */ }
}

// ── Auth Steps ───────────────────────────────────────────────────────────────

function getMicrosoftAuthCode() {
  const { BrowserWindow } = require('electron');

  return new Promise((resolve, reject) => {
    let settled = false;

    // settle() ensures we only resolve/reject once, so the 'closed'
    // event firing after win.destroy() doesn't cause a double-rejection
    function settle(fn, val) {
      if (settled) return;
      settled = true;
      fn(val);
    }

    const win = new BrowserWindow({
      width: 520,
      height: 600,
      title: 'Sign in with Microsoft',
      show: false,
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
      },
    });

    win.once('ready-to-show', () => win.show());

    function tryHandleUrl(url) {
      if (!url || !url.startsWith(REDIRECT_URI)) return false;
      try {
        const parsed = new URL(url);
        const code = parsed.searchParams.get('code');
        const error = parsed.searchParams.get('error');
        // Destroy window after a tick so Electron can clean up gracefully
        setImmediate(() => { try { win.destroy(); } catch {} });
        if (code) settle(resolve, code);
        else settle(reject, new Error(error || 'Microsoft login cancelled'));
      } catch (e) {
        settle(reject, e);
      }
      return true;
    }

    win.webContents.on('will-redirect', (_, url) => tryHandleUrl(url));
    win.webContents.on('will-navigate', (_, url) => tryHandleUrl(url));
    win.webContents.on('did-navigate', (_, url) => tryHandleUrl(url));
    win.webContents.on('did-navigate-in-page', (_, url) => tryHandleUrl(url));

    // Fallback: poll the current URL every 500ms in case navigation events miss it
    const pollInterval = setInterval(() => {
      if (settled) { clearInterval(pollInterval); return; }
      try {
        const url = win.webContents.getURL();
        if (tryHandleUrl(url)) clearInterval(pollInterval);
      } catch { clearInterval(pollInterval); }
    }, 500);

    win.on('closed', () => {
      clearInterval(pollInterval);
      settle(reject, new Error('Login window was closed'));
    });

    win.loadURL(AUTH_URL);
  });
}

async function getMicrosoftTokens(code) {
  const res = await httpsPost('https://login.live.com/oauth20_token.srf', {
    client_id: MS_CLIENT_ID,
    code,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI,
    scope: 'XboxLive.signin offline_access',
  });
  if (!res.access_token) throw new Error('MS token failed: ' + JSON.stringify(res));
  return res;
}

async function refreshMicrosoftToken(refreshToken) {
  const res = await httpsPost('https://login.live.com/oauth20_token.srf', {
    client_id: MS_CLIENT_ID,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
    redirect_uri: REDIRECT_URI,
    scope: 'XboxLive.signin offline_access',
  });
  if (!res.access_token) throw new Error('MS token refresh failed');
  return res;
}

async function getXboxLiveToken(msAccessToken) {
  const res = await httpsPost('https://user.auth.xboxlive.com/user/authenticate', {
    Properties: {
      AuthMethod: 'RPS',
      SiteName: 'user.auth.xboxlive.com',
      RpsTicket: `d=${msAccessToken}`,
    },
    RelyingParty: 'http://auth.xboxlive.com',
    TokenType: 'JWT',
  });
  if (!res.Token) throw new Error('XBL token failed: ' + JSON.stringify(res));
  return { token: res.Token, userHash: res.DisplayClaims.xui[0].uhs };
}

async function getXSTSToken(xblToken) {
  const res = await httpsPost('https://xsts.auth.xboxlive.com/xsts/authorize', {
    Properties: { SandboxId: 'RETAIL', UserTokens: [xblToken] },
    RelyingParty: 'rp://api.minecraftservices.com/',
    TokenType: 'JWT',
  });
  if (res.XErr) {
    const msgs = {
      2148916233: 'No Xbox profile found. Create one at xbox.com.',
      2148916235: 'Xbox Live is unavailable in your region.',
      2148916238: 'Child account — add to a family at xbox.com.',
    };
    throw new Error(msgs[res.XErr] || `XSTS error code: ${res.XErr}`);
  }
  if (!res.Token) throw new Error('XSTS token failed: ' + JSON.stringify(res));
  return res.Token;
}

async function getMinecraftToken(xstsToken, userHash) {
  const res = await httpsPost(
    'https://api.minecraftservices.com/authentication/login_with_xbox',
    { identityToken: `XBL3.0 x=${userHash};${xstsToken}` }
  );
  if (!res.access_token) throw new Error('Minecraft token failed: ' + JSON.stringify(res));
  return res.access_token;
}

async function getMinecraftProfile(mcAccessToken) {
  const ownership = await httpsGet(
    'https://api.minecraftservices.com/entitlements/mcstore',
    mcAccessToken
  );
  const items = ownership.items || [];
  const ownsGame = items.some(i => i.name === 'product_minecraft' || i.name === 'game_minecraft');
  if (!ownsGame) throw new Error('This account does not own Minecraft Java Edition.');

  const profile = await httpsGet(
    'https://api.minecraftservices.com/minecraft/profile',
    mcAccessToken
  );
  if (!profile.name) throw new Error('Could not fetch Minecraft profile.');
  return { username: profile.name, uuid: profile.id };
}

// ── Public API ───────────────────────────────────────────────────────────────

async function login() {
  const code = await getMicrosoftAuthCode();
  const msTokens = await getMicrosoftTokens(code);
  const { token: xblToken, userHash } = await getXboxLiveToken(msTokens.access_token);
  const xstsToken = await getXSTSToken(xblToken);
  const mcAccessToken = await getMinecraftToken(xstsToken, userHash);
  const { username, uuid } = await getMinecraftProfile(mcAccessToken);

  const expiresAt = Date.now() + msTokens.expires_in * 1000;
  saveAuth({ refreshToken: msTokens.refresh_token, mcAccessToken, username, uuid, expiresAt });
  return { username, uuid, mcAccessToken };
}

async function tryRestoreSession() {
  const saved = loadAuth();
  if (!saved) return null;

  try {
    if (saved.expiresAt && Date.now() < saved.expiresAt - 60000) {
      return { username: saved.username, uuid: saved.uuid, mcAccessToken: saved.mcAccessToken };
    }
    const msTokens = await refreshMicrosoftToken(saved.refreshToken);
    const { token: xblToken, userHash } = await getXboxLiveToken(msTokens.access_token);
    const xstsToken = await getXSTSToken(xblToken);
    const mcAccessToken = await getMinecraftToken(xstsToken, userHash);
    const { username, uuid } = await getMinecraftProfile(mcAccessToken);
    const expiresAt = Date.now() + msTokens.expires_in * 1000;
    saveAuth({ refreshToken: msTokens.refresh_token, mcAccessToken, username, uuid, expiresAt });
    return { username, uuid, mcAccessToken };
  } catch (err) {
    console.warn('[msauth] Session restore failed:', err.message);
    clearAuth();
    return null;
  }
}

function logout() {
  clearAuth();
}

module.exports = { login, tryRestoreSession, logout };
