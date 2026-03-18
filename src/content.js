/**
 * 在配置了「适用地址」的页面上，自动将当前动码填入 2FA 输入框。
 */
const STORAGE_KEY = 'totp_entries';

/** 当前页是否匹配配置的适用地址：仅主机则按主机匹配，带路径则按完整 URL 前缀匹配（只在动码页填） */
function urlMatches(configuredUrl, pageOrigin, pagePathname, pageHostname) {
  const s = configuredUrl.trim().toLowerCase();
  if (!s) return false;
  try {
    const u = new URL(s.startsWith('http') ? s : 'https://' + s);
    const hasPath = u.pathname && u.pathname !== '/';
    if (hasPath) {
      const full = u.origin + u.pathname.replace(/\/$/, '');
      const pageFull = pageOrigin + pagePathname.replace(/\/$/, '');
      return pageFull === full || pageFull.startsWith(full + '/');
    }
    return pageHostname === u.hostname || pageHostname.endsWith('.' + u.hostname);
  } catch (_) {
    return false;
  }
}

function getStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_KEY], (r) => resolve(r[STORAGE_KEY] || []));
  });
}

function findOtpInput() {
  const sel = [
    'input[autocomplete="one-time-code"]',
    'input#js_inputpass',
    'input[name="inputpass"]',
    'input[placeholder*="动态密码"]',
    'input[placeholder*="码"]',
    'input[name*="otp"]',
    'input[name*="code"]',
    'input[placeholder*="code"]',
    'input[placeholder*="OTP"]',
    'input[type="text"][maxlength="6"]',
    'input[type="tel"][maxlength="6"]',
    'input.input-otp',
    'input[data-otp]',
    'input.form-control[placeholder*="密码"]',
  ];
  for (const s of sel) {
    try {
      const el = document.querySelector(s);
      if (el && !el.disabled && el.type !== 'hidden') return el;
    } catch (_) {}
  }
  return null;
}

function setInputValue(input, value) {
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

async function tryFill() {
  const pageOrigin = location.origin;
  const pagePathname = location.pathname || '/';
  const pageHostname = location.hostname;
  const entries = await getStorage();
  const match = entries.find((e) => {
    const urls = e.urls || [];
    return urls.some((u) => urlMatches(u, pageOrigin, pagePathname, pageHostname));
  });
  if (!match) return;
  const input = findOtpInput();
  if (!input) return;
  const code = await TOTP.getTOTP(match.secret);
  if (!code || code.length !== 6) return;
  setInputValue(input, code);
}

getStorage().then((entries) => {
  const hasMatch = entries.some((e) => (e.urls || []).length > 0);
  if (!hasMatch) return;
  tryFill();
  // 页面可能动态渲染输入框，延迟再试
  setTimeout(tryFill, 1500);
  setTimeout(tryFill, 3000);
});
