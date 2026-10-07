import allowlist from './allowlist.json' with { type: 'json' };
import { normalizeURL } from './normalize.js';
import { bodyShape, headerShape, isApproved, PendingSamples } from './capture.js';

const WS_URL = allowlist.gateway_ws_url;
const ALLOWED_ORIGINS = new Set(allowlist.allowed_origins || []);
const CAPTURE_FILTER = { urls: [...ALLOWED_ORIGINS].map((origin) => `${origin}/*`) };

let ws = null;
let reconnectTimer = null;

// ---------- Phase 1: Traffic capture ----------

const sampleBuffer = [];
const pendingSamples = new PendingSamples();
const MAX_BUFFER = 200;
let flushInFlight = false;

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if ((details.type !== 'xmlhttprequest' && details.type !== 'fetch') || !isApproved(details, ALLOWED_ORIGINS)) return;
    const parsed = new URL(details.url);
    const sample = {
      method: details.method,
      url_template: `${parsed.pathname}${parsed.search ? '?<query-schema>' : ''}`,
      host: parsed.origin,
      request_body: bodyShape(details.requestBody),
      request_headers: {},
      response_body: '',
      is_static_asset: false,
      timestamp: Date.now(),
      request_id: details.requestId,
    };
    pendingSamples.set(details.requestId, sample);
  },
  CAPTURE_FILTER,
  ['requestBody']
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const sample = pendingSamples.get(details.requestId);
    if (!sample || !isApproved(details, ALLOWED_ORIGINS)) { pendingSamples.delete(details.requestId); return; }
    sample.request_headers = headerShape(details.requestHeaders || []);
  },
  CAPTURE_FILTER,
  ['requestHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const sample = pendingSamples.get(details.requestId);
    if (!sample || !isApproved(details, ALLOWED_ORIGINS)) { pendingSamples.delete(details.requestId); return; }
    pendingSamples.delete(details.requestId);
    sample.status_code = details.statusCode;
    sample.response_headers = headerShape(details.responseHeaders || []);
    // normalize URL into template
    const [template] = normalizeURL(details.url, sample.host);
    sample.template = template;
    sample.url_template = template;
    sample.param_values = {};
    sample.response_body = '';
    sampleBuffer.push(sample);
    if (sampleBuffer.length > MAX_BUFFER) sampleBuffer.shift();
  },
  CAPTURE_FILTER,
  ['responseHeaders']
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => { pendingSamples.delete(details.requestId); },
  CAPTURE_FILTER
);

// ---------- Periodic discovery flush ----------

setInterval(async () => {
  pendingSamples.prune();
  if (sampleBuffer.length === 0 || flushInFlight) return;
  flushInFlight = true;
  const batch = sampleBuffer.splice(0, sampleBuffer.length);
  try {
    const response = await fetch(allowlist.discovery_url, {
      method: 'POST',
      signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ samples: batch }),
    });
    if (!response.ok) throw new Error('discovery refused batch');
  } catch (e) {
    // reconnect later; re-buffer on failure
    sampleBuffer.push(...batch);
    if (sampleBuffer.length > MAX_BUFFER) sampleBuffer.splice(0, sampleBuffer.length - MAX_BUFFER);
  } finally {
    flushInFlight = false;
  }
}, allowlist.flush_interval_ms || 30000);

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
