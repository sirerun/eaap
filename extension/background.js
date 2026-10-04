import allowlist from './allowlist.json' with { type: 'json' };
import { normalizeURL } from './normalize.js';
import { executeDOMSimulation } from './executor.js';

const WS_URL = allowlist.gateway_ws_url;
const ALLOWED_ORIGINS = allowlist.allowed_origins;

let ws = null;
let reconnectTimer = null;

// ---------- Phase 1: Traffic capture ----------

const sampleBuffer = [];
const pendingSamples = new Map();
const MAX_BUFFER = 200;

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== 'xmlhttprequest' && details.type !== 'fetch') return;
    const sample = {
      method: details.method,
      url_template: null,
      host: new URL(details.url).origin,
      request_body: details.requestBody
        ? decompressBody(details.requestBody) : '',
      request_headers: {},
      response_body: '',
      is_static_asset: false,
      timestamp: Date.now(),
      request_id: details.requestId,
    };
    pendingSamples.set(details.requestId, sample);
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const sample = pendingSamples.get(details.requestId);
    if (!sample) return;
    sample.request_headers = Object.fromEntries((details.requestHeaders || []).map((header) => {
      const key = header.name.toLowerCase();
      const value = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key'].includes(key)
        ? '[REDACTED]'
        : String(header.value || '');
      return [key, value];
    }));
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const sample = pendingSamples.get(details.requestId);
    if (!sample) return;
    pendingSamples.delete(details.requestId);
    sample.status_code = details.statusCode;
    sample.response_headers = Object.fromEntries(
      (details.responseHeaders || []).map((h) => [h.name.toLowerCase(), h.value])
    );
    // normalize URL into template
    const [template, params] = normalizeURL(details.url, sample.host);
    sample.template = template;
    sample.url_template = template;
    sample.param_values = Object.fromEntries(params.map((value, i) => ['param' + (i + 1), value]));
    sample.response_body = '';
    sampleBuffer.push(sample);
    if (sampleBuffer.length > MAX_BUFFER) sampleBuffer.shift();
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

function decompressBody(rb) {
  if (rb.raw && rb.raw[0]) {
    const bytes = new Uint8Array(rb.raw[0].bytes);
    return new TextDecoder().decode(bytes).slice(0, 4096);
  }
  return '';
}

// ---------- Periodic discovery flush ----------

setInterval(async () => {
  if (sampleBuffer.length === 0) return;
  const batch = sampleBuffer.splice(0, sampleBuffer.length);
  try {
    await fetch('http://localhost:8080/internal/discovery', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ samples: batch }),
    });
  } catch (e) {
    // reconnect later; re-buffer on failure
    sampleBuffer.push(...batch);
  }
}, 30000);

// ---------- Phase 2: WebSocket + execution ----------

function connect() {
  ws = new WebSocket(WS_URL);
  ws.onopen = () => console.log('[EaaP] connected to gateway');
  ws.onmessage = (ev) => {
    try {
      void handleEnvelope(JSON.parse(ev.data));
    } catch (error) {
      console.error('[EaaP] invalid envelope', error);
    }
  };
  ws.onclose = () => {
    reconnectTimer = setTimeout(connect, 5000 + Math.random() * 3000);
  };
  ws.onerror = () => ws.close();
}

connect();

async function handleEnvelope(env) {
  // RFC 6.4: SSRF allowlist enforcement on the client
  const target = new URL(env.target_url);
  if (!ALLOWED_ORIGINS.includes(target.origin)) {
    sendResponse(env.envelope_id, { error: 'origin not allowlisted' });
    return;
  }

  try {
    if (env.executionMode === 'SYNTHETIC_FETCH') {
      await execSyntheticFetch(env);
    } else if (env.executionMode === 'DOM_SIMULATION') {
      await executeDOMSimulation(env, sendResponse);
    } else {
      sendResponse(env.envelope_id, { error: 'unknown executionMode' });
    }
  } catch (e) {
    sendResponse(env.envelope_id, { error: String(e && e.message || e) });
  }
}

async function execSyntheticFetch(env) {
  const resp = await fetch(env.target_url, {
    method: env.method,
    headers: env.headers || {},
    body: env.body && env.method !== 'GET' && env.method !== 'HEAD'
      ? (typeof env.body === 'string' ? env.body : JSON.stringify(env.body))
      : undefined,
    credentials: 'include', // session reuse per RFC 3.2
  });
  const text = await resp.text();
  sendResponse(env.envelope_id, {
    status_code: resp.status,
    headers: Object.fromEntries(resp.headers.entries()),
    body: maybeParseJSON(text),
  });
}

function maybeParseJSON(text) {
  try { return JSON.parse(text); } catch { return text; }
}

function sendResponse(envelopeID, partial) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ envelope_id: envelopeID, timestamp: new Date().toISOString(), ...partial }));
  }
}
