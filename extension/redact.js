const SENSITIVE_HEADERS = new Set([
  'authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key',
]);

export function redactHeaders(headers = []) {
  return Object.fromEntries(headers.map(({ name, value }) => {
    const key = String(name || '').toLowerCase();
    return [key, SENSITIVE_HEADERS.has(key) ? '[REDACTED]' : String(value || '')];
  }));
}
