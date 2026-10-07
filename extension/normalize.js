const utf8 = new TextEncoder();

// Static path text must come from trusted deployment configuration, never from
// a heuristic over captured values. Undeclared routes retain only path shape.
export function normalizeURL(rawURL, approvedTemplates = []) {
  try {
    const url = new URL(rawURL);
    const segments = url.pathname.split('/').filter(Boolean);
    if (segments.length > 64) return ['/{path}' + (url.search ? '?<query-schema>' : ''), []];
    let output = segments.map((_, index) => '{param' + (index + 1) + '}');
    if (Array.isArray(approvedTemplates)) {
      for (const pattern of approvedTemplates.slice(0, 64)) {
        if (typeof pattern !== 'string' || pattern.length > 4096 || utf8.encode(pattern).byteLength > 4096 ||
            !pattern.startsWith('/') || pattern.includes('//') || pattern.endsWith('/')) continue;
        const parts = pattern.slice(1).split('/');
        if (parts.length !== segments.length) continue;
        let index = 0;
        const normalized = [];
        let matches = true;
        for (let i = 0; i < parts.length; i++) {
          if (/^\{[A-Za-z][A-Za-z0-9_]{0,31}\}$/.test(parts[i])) {
            normalized.push('{param' + (++index) + '}');
          } else if (/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(parts[i]) && parts[i] === segments[i]) {
            normalized.push(parts[i]);
          } else { matches = false; break; }
        }
        if (matches) { output = normalized; break; }
      }
    }
    const template = '/' + output.join('/') + (url.search ? '?<query-schema>' : '');
    return [template === '/' ? '' : template, []];
  } catch { return ['', []]; }
}
