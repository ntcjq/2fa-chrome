const STORAGE_KEY = 'totp_entries';

function getStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_KEY], (result) => {
      resolve(result[STORAGE_KEY] || []);
    });
  });
}

function setStorage(entries) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEY]: entries }, resolve);
  });
}

function safeDecodeLabel(value) {
  const raw = String(value || '');
  try {
    return decodeURIComponent(raw);
  } catch (_) {
    return raw;
  }
}

function parseOtpauth(url) {
  const raw = String(url || '').trim();
  if (!/^otpauth:\/\//i.test(raw)) return null;
  try {
    const u = new URL(raw);
    const type = (u.hostname || '').toLowerCase();
    let labelPath = u.pathname || '';
    if (type) {
      if (type !== 'totp') return null;
      labelPath = labelPath.replace(/^\/+/, '');
    } else {
      const lowerPath = labelPath.toLowerCase();
      if (!lowerPath.startsWith('/totp')) return null;
      labelPath = labelPath.replace(/^\/totp\/?/, '');
    }

    let label = safeDecodeLabel(labelPath).replace(/\+/g, ' ').trim();
    const secret = (u.searchParams.get('secret') || '').replace(/[\s-]/g, '');
    if (!secret) return null;
    let issuer = (u.searchParams.get('issuer') || '').trim();
    let name = label;
    const colonIndex = label.indexOf(':');
    if (colonIndex >= 0) {
      const labelIssuer = label.slice(0, colonIndex).trim();
      const labelName = label.slice(colonIndex + 1).trim();
      if (!issuer && labelIssuer) issuer = labelIssuer;
      name = labelName || labelIssuer;
    }
    return { name: name || '未命名', secret, issuer };
  } catch (_) {
    return null;
  }
}

function parseUrls(text) {
  return [...new Set(
    (text || '').split(/[\n,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)
  )];
}

function normalizeUrlForDisplay(url) {
  const s = (url || '').trim().toLowerCase();
  if (!s) return '';
  try {
    const u = new URL(s.startsWith('http') ? s : 'https://' + s);
    const hasPath = u.pathname && u.pathname !== '/';
    if (hasPath) return u.origin + u.pathname.replace(/\/$/, '');
    return u.hostname;
  } catch (_) {
    return s;
  }
}

async function addEntry(entry) {
  const entries = await getStorage();
  const urls = entry.urls ? parseUrls(entry.urls) : [];
  const newEntry = {
    id: crypto.randomUUID ? crypto.randomUUID() : 'id-' + Date.now(),
    name: entry.name,
    secret: entry.secret,
    issuer: entry.issuer || '',
    note: entry.note || '',
    urls: urls.map(normalizeUrlForDisplay),
  };
  entries.push(newEntry);
  await setStorage(entries);
  return entries;
}

// 同步执行复制，必须在用户点击的同一同步调用栈内完成，否则 Safari 会拒绝
function copyToClipboardSync(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  ta.style.top = '0';
  ta.style.opacity = '0';
  ta.style.pointerEvents = 'none';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } finally {
    document.body.removeChild(ta);
  }
  return ok;
}

function showCopiedToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message || '已复制到剪贴板';
  toast.classList.add('visible');
  clearTimeout(toast._tid);
  toast._tid = setTimeout(() => toast.classList.remove('visible'), 1500);
}

function buildLabel(entry) {
  if (entry.issuer) return entry.issuer + ' - ' + entry.name;
  return entry.name || '未命名';
}

function showInlineMessage(container, text, isError) {
  const msg = document.createElement('div');
  msg.className = 'inline-msg ' + (isError ? 'inline-msg-error' : 'inline-msg-ok');
  msg.textContent = text;
  container.insertBefore(msg, container.firstChild);
  setTimeout(() => msg.remove(), 3000);
}

async function renderEntries(entries) {
  const app = document.getElementById('app');
  if (entries.length === 0) {
    app.innerHTML = `
      <div class="empty-state minimal">
        <p class="empty-title">暂无数据</p>
      </div>
    `;
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    const code = await TOTP.getTOTP(entry.secret);
    const remaining = TOTP.getRemainingSeconds();
    const labelText = entry.note
      ? buildLabel(entry) + ' (' + entry.note + ')'
      : buildLabel(entry);
    const div = document.createElement('div');
    div.className = 'entry';
    div.dataset.id = entry.id;
    div.innerHTML = `
      <div class="entry-main">
        <div class="label">${escapeHtml(labelText)}</div>
        <div class="code" data-code="${escapeHtml(code)}">${code}</div>
      </div>
      <div class="meta">
        <span class="seconds">${remaining}s</span>
      </div>
    `;
    div.addEventListener('click', () => {
      // Safari 要求剪贴板写入在用户手势内同步完成，故从 DOM 取当前码并立即 execCommand('copy')
      const codeEl = div.querySelector('.code');
      const currentCode = codeEl ? codeEl.textContent.trim() : '';
      if (!currentCode) {
        showCopiedToast('复制失败');
        return;
      }
      if (copyToClipboardSync(currentCode)) {
        showCopiedToast();
      } else {
        showCopiedToast('复制失败');
      }
    });
    fragment.appendChild(div);
  }
  app.innerHTML = '';
  app.appendChild(fragment);
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

async function refreshCodes() {
  const entries = await getStorage();
  const app = document.getElementById('app');
  const containers = app.querySelectorAll('.entry');
  const remaining = TOTP.getRemainingSeconds();
  containers.forEach(async (el, i) => {
    const entry = entries[i];
    if (!entry) return;
    const code = await TOTP.getTOTP(entry.secret);
    const codeEl = el.querySelector('.code');
    const secEl = el.querySelector('.seconds');
    if (codeEl) {
      codeEl.textContent = code;
      codeEl.dataset.code = code;
    }
    if (secEl) secEl.textContent = remaining + 's';
  });
}

function openOptionsPage() {
  const runtime = chrome && chrome.runtime ? chrome.runtime : null;
  if (runtime && runtime.openOptionsPage) {
    runtime.openOptionsPage();
    return;
  }

  const url = runtime && runtime.getURL ? runtime.getURL('options.html') : 'options.html';
  if (chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url });
  } else {
    window.open(url, '_blank');
  }
}

async function init() {
  const entries = await getStorage();
  await renderEntries(entries);
  setInterval(refreshCodes, 1000);
  document.getElementById('open-settings').addEventListener('click', (e) => {
    e.preventDefault();
    openOptionsPage();
  });
}

init();
