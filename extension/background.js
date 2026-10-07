import allowlist from './allowlist.json' with { type: 'json' };
import { normalizeURL } from './normalize.js';
import { redactHeaders } from './redact.js';

const WS_URL = allowlist.gateway_ws_url;

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
    sample.request_headers = redactHeaders(details.requestHeaders || []);
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
    sample.response_headers = redactHeaders(details.responseHeaders || []);
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
  ws.onopen = async () => {
    const { pairingToken } = await chrome.storage.local.get('pairingToken');
    if (!pairingToken) { ws.close(); return; }
    ws.send(JSON.stringify({ pairing_token: pairingToken }));
    await chrome.storage.local.remove('pairingToken');
    console.log('[EaaP] pairing submitted');
  };
  ws.onmessage = (ev) => {
    // T4.1 never executes incoming work. Durable, single-use T4.2 grants are
    // required before any envelope can reach a browser effect.
    try {
      const message = JSON.parse(ev.data);
      if (message?.type === 'pairing_accepted') return;
      sendResponse(message?.envelope_id, { error: 'dispatch disabled pending T4.2 grant gate' });
    }
    catch { ws.close(); }
  };
  ws.onclose = () => {
    reconnectTimer = setTimeout(connect, 5000 + Math.random() * 3000);
  };
  ws.onerror = () => ws.close();
}

connect();

function sendResponse(envelopeID, partial) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ envelope_id: envelopeID, timestamp: new Date().toISOString(), ...partial }));
  }
}
