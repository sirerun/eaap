const NUMERIC = /^\d{2,}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HASH = /^[0-9a-fA-F]{16,}$/;
const OPAQUE = /^[A-Za-z0-9_-]{20,}$/;
export function isDynamicSeg(segment) {
  return NUMERIC.test(segment) || UUID.test(segment) || HASH.test(segment) || OPAQUE.test(segment);
}

export function normalizeURL(rawURL) {
  try {
    const url = new URL(rawURL, 'http://localhost');
    let index = 0;
    const segments = url.pathname.split('/').filter(Boolean).map((segment) => {
      if (!isDynamicSeg(segment) && /^[a-z][a-z0-9_-]{0,31}$/.test(segment) && !/(token|auth|secret|session|credential|key)/i.test(segment)) return segment;
      index += 1;
      return `{param${index}}`;
    });
    const template = `/${segments.join('/')}${url.search ? '?<query-schema>' : ''}`;
    return [template === '/' && !url.search ? '' : template, []];
  } catch {
    return ['', []];
  }
}
