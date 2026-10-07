export function isApproved(details, allowedOrigins) {
  try {
    const origin = new URL(details.url).origin;
    const initiator = details.initiator || details.documentUrl;
    return allowedOrigins.has(origin) && !!initiator && allowedOrigins.has(new URL(initiator).origin);
  } catch { return false; }
}

export function bodyShape(body) {
  if (!body) return '';
  if (body.formData) {
    const shape = {};
    for (const [name, value] of Object.entries(body.formData)) {
      const key = safeFieldName(name);
      shape[key] = Array.isArray(value) ? 'array<string>' : 'string';
    }
    return JSON.stringify(shape);
  }
  if (body.raw?.length) {
    try {
      const bytes = body.raw.flatMap(part => Array.from(new Uint8Array(part.bytes || []))).slice(0, 65536);
      const parsed = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes)));
      return JSON.stringify(valueShape(parsed));
    } catch { return JSON.stringify({'$raw':'binary'}); }
  }
  return '';
}

function safeFieldName(name) {
  return /^(password|passwd|.*token.*|.*secret.*|.*auth.*|.*cookie.*|.*credential.*|.*api.?key.*|.*email.*|.*phone.*)$/i.test(name) || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(name) ? '<sensitive-field>' : name;
}

function valueShape(value) {
  if (Array.isArray(value)) return value.length ? `array<${JSON.stringify(valueShape(value[0]))}>` : 'array<unknown>';
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [safeFieldName(key), valueShape(child)]));
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
  for (const {name, value = ''} of headers) {
    const key = String(name || '').toLowerCase();
    if (key === 'content-type') {
      const mediaType = String(value).split(';')[0].trim();
      if (/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mediaType)) output[key] = mediaType;
    } else if (key && /^[a-z0-9-]{1,64}$/i.test(key)) output[key] = 'present';
  }
  return output;
}
