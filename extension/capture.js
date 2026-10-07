export function isApproved(details, allowedOrigins) {
  try {
    if (typeof details.url !== 'string' || details.url.length > 8192) return false;
    const origin = new URL(details.url).origin;
    const initiator = details.initiator || details.documentUrl;
    if (typeof initiator !== 'string' || initiator.length > 8192) return false;
    return allowedOrigins.has(origin) && !!initiator && allowedOrigins.has(new URL(initiator).origin);
  } catch { return false; }
}

export function bodyShape(body) {
  if (!body) return '';
  if (body.formData) {
    const shape = {};
    let fields = 0;
    for (const name in body.formData) {
      if (!Object.hasOwn(body.formData, name)) continue;
      if (++fields > 64) break;
      const value = body.formData[name];
      const key = safeFieldName(name);
      shape[key] = Array.isArray(value) ? 'array<string>' : 'string';
    }
    return JSON.stringify(shape);
  }
  if (body.raw?.length) {
    try {
      // Validate all sizes before copying. Never expand an upload into a
      // number array and apply a byte limit only after that allocation.
      if (body.raw.length > 64) return JSON.stringify({'$raw':'oversize'});
      let total = 0;
      for (const part of body.raw) {
        if (!(part.bytes instanceof ArrayBuffer)) return JSON.stringify({'$raw':'binary'});
        total += part.bytes.byteLength;
        if (total > 65536) return JSON.stringify({'$raw':'oversize'});
      }
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const part of body.raw) {
        bytes.set(new Uint8Array(part.bytes), offset);
        offset += part.bytes.byteLength;
      }
      const parsed = JSON.parse(new TextDecoder().decode(bytes));
      const shaped = JSON.stringify(valueShape(parsed));
      return shaped.length <= 65536 ? shaped : JSON.stringify({'$shape':'oversize'});
    } catch { return JSON.stringify({'$raw':'binary'}); }
  }
  return '';
}

function safeFieldName(name) {
  return /^(password|passwd|.*token.*|.*secret.*|.*auth.*|.*cookie.*|.*credential.*|.*api.?key.*|.*email.*|.*phone.*)$/i.test(name) || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(name) ? '<sensitive-field>' : name;
}

function valueShape(value, depth = 0) {
  if (depth >= 8) return 'truncated';
  if (Array.isArray(value)) return value.length ? `array<${JSON.stringify(valueShape(value[0], depth + 1))}>` : 'array<unknown>';
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).slice(0, 64).map(([key, child]) => [safeFieldName(key), valueShape(child, depth + 1)]));
  }
  return typeName(value);
}

function typeName(value) {
  if (value === null) return 'null';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

export function headerShape(headers) {
  const output = {};
  let count = 0;
  for (const {name, value = ''} of headers) {
    if (++count > 64) break;
    const key = String(name || '').toLowerCase();
    if (key === 'content-type') {
      if (typeof value !== 'string' || value.length > 256) continue;
      const mediaType = value.split(';')[0].trim();
      if (/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mediaType)) output[key] = mediaType;
    } else if (key && /^[a-z0-9-]{1,64}$/i.test(key)) output[key] = 'present';
  }
  return output;
}


// Only value-free metadata enters this cache. Count and age are bounded even
// when a browser never reports completion/error for a request.
export class PendingSamples {
  #entries = new Map();
  constructor({maxEntries = 200, maxAgeMs = 30000, now = Date.now} = {}) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 200 ||
        !Number.isFinite(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > 30000) {
      throw new Error('invalid capture cache bounds');
    }
    this.maxEntries = maxEntries; this.maxAgeMs = maxAgeMs; this.now = now;
  }
  prune() {
    const now = this.now();
    for (const [key, entry] of this.#entries) if (entry.expiresAt <= now) this.#entries.delete(key);
  }
  set(key, sample) {
    this.prune();
    this.#entries.delete(key);
    while (this.#entries.size >= this.maxEntries) this.#entries.delete(this.#entries.keys().next().value);
    this.#entries.set(key, {sample, expiresAt: this.now() + this.maxAgeMs});
    return this;
  }
  get(key) { this.prune(); return this.#entries.get(key)?.sample; }
  delete(key) { return this.#entries.delete(key); }
  get size() { this.prune(); return this.#entries.size; }
}
