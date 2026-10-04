const NUMERIC = /^\d{2,}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HASH = /^[0-9a-fA-F]{16,}$/;
const OPAQUE = /^[A-Za-z0-9_-]{20,}$/;
const VOLATILE_PARAMS = new Set([
  'ts', 'timestamp', '_', 'nonce', 'cache_bust', 'cb', 'sid', 'request_id',
]);

export function isDynamicSeg(segment) {
  return NUMERIC.test(segment) || UUID.test(segment) || HASH.test(segment) || OPAQUE.test(segment);
}

export function normalizeURL(rawURL) {
  try {
    const url = new URL(rawURL, 'http://localhost');
    const params = [];
    let index = 0;
    const segments = url.pathname.split('/').filter(Boolean).map((segment) => {
      if (!isDynamicSeg(segment)) return segment;
      params.push(segment);
      index += 1;
      return `{param${index}}`;
    });
    for (const key of [...url.searchParams.keys()]) {
      if (VOLATILE_PARAMS.has(key.toLowerCase())) url.searchParams.delete(key);
    }
    const query = url.searchParams.toString();
    const template = `/${segments.join('/')}${query ? `?${query}` : ''}`;
    return [template === '/' && !query ? '' : template, params];
  } catch {
    return [rawURL, []];
  }
}
