export async function executeDOMSimulation(env, sendResponse) {
  try {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find((candidate) => {
      if (!candidate.id || !candidate.url) return false;
      try {
        return new URL(candidate.url).origin === env.origin;
      } catch {
        return false;
      }
    });
    if (!tab) {
      sendResponse(env.envelope_id, { error: 'no open tab for target origin' });
      return;
    }

    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: domSimulate,
      args: [env],
    });
    sendResponse(env.envelope_id, result?.result || { error: 'page returned no result' });
  } catch (error) {
    sendResponse(env.envelope_id, { error: String(error?.message || error) });
  }
}

function domSimulate(env) {
  return new Promise((resolve) => {
    const root = env.css_target ? document.querySelector(env.css_target) : document.body;
    if (!root) {
      resolve({ error: 'css target not found' });
      return;
    }

    for (const [selector, value] of Object.entries(env.input_fields || {})) {
      const element = document.querySelector(selector);
      if (!element) {
        resolve({ error: `input not found: ${selector}` });
        return;
      }
      const prototype = element instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
      if (!setter) {
        resolve({ error: `input cannot be set: ${selector}` });
        return;
      }
      setter.call(element, value);
      element.dispatchEvent(new Event('input', { bubbles: true }));
      element.dispatchEvent(new Event('change', { bubbles: true }));
    }

    const trigger = env.trigger_event || 'click';
    const target = env.trigger_selector
      ? document.querySelector(env.trigger_selector)
      : root;
    if (!target) {
      resolve({ error: 'trigger target not found' });
      return;
    }

    setTimeout(() => {
      if (trigger === 'click') {
        target.click();
      } else {
        target.dispatchEvent(new Event(trigger, { bubbles: true }));
      }
      const timeoutMs = env.timeout_ms || 30000;
      const startedAt = Date.now();
      const check = setInterval(() => {
        if (Date.now() - startedAt > timeoutMs) {
          clearInterval(check);
          resolve({ status_code: 504, error: 'timeout waiting for page activity to settle' });
          return;
        }
        const recentResources = performance.getEntriesByType('resource')
          .filter((entry) => Date.now() - (performance.timeOrigin + entry.startTime) < 2000);
        if (recentResources.length === 0 && Date.now() - startedAt > 1000) {
          clearInterval(check);
          resolve({
            status_code: 200,
            dom_mutation: 'settled',
            body: { extracted_text: document.body.innerText.slice(0, 2048) },
          });
        }
      }, 250);
    }, 100);
  });
}

export function startSessionObserver() {
  setInterval(() => {
    chrome.cookies.getAll({}, (cookies) => {
      const hasSession = cookies.some((cookie) => /sess|auth|token|jwt/i.test(cookie.name));
      if (!hasSession) {
        fetch('http://localhost:8080/internal/session-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_valid: false }),
        }).catch(() => {});
      }
    });
  }, 60000);
}
