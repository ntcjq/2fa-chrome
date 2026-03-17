const STORAGE_KEY = 'totp_entries';
const extensionApi = typeof browser !== 'undefined'
  ? browser
  : (typeof chrome !== 'undefined' ? chrome : null);

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value == null ? '' : String(value);
  return div.innerHTML;
}

function showFatalMessage(text) {
  const list = document.getElementById('entries-list');
  if (list) {
    list.innerHTML = '<li style="color:#c62828">' + escapeHtml(text) + '</li>';
  }
}

function showMessage(el, text, type) {
  const msg = document.createElement('div');
  msg.className = 'message ' + type;
  msg.textContent = text;
  el.insertBefore(msg, el.firstChild);
  setTimeout(function() { msg.remove(); }, 3000);
}

function getStorageArea() {
  if (extensionApi && extensionApi.storage && extensionApi.storage.local) {
    return extensionApi.storage.local;
  }
  return null;
}

function getStorage() {
  return new Promise(function(resolve) {
    const storage = getStorageArea();
    if (!storage) {
      resolve([]);
      return;
    }
    storage.get([STORAGE_KEY], function(result) {
      resolve(result[STORAGE_KEY] || []);
    });
  });
}

function setStorage(entries) {
  return new Promise(function(resolve) {
    const storage = getStorageArea();
    if (!storage) {
      resolve();
      return;
    }
    storage.set({ [STORAGE_KEY]: entries }, resolve);
  });
}

function generateEntryId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2);
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
    const parsedUrl = new URL(raw);
    const type = (parsedUrl.hostname || '').toLowerCase();
    let labelPath = parsedUrl.pathname || '';
    if (type) {
      if (type !== 'totp') return null;
      labelPath = labelPath.replace(/^\/+/, '');
    } else {
      const lowerPath = labelPath.toLowerCase();
      if (!lowerPath.startsWith('/totp')) return null;
      labelPath = labelPath.replace(/^\/totp\/?/, '');
    }

    let label = safeDecodeLabel(labelPath).replace(/\+/g, ' ').trim();
    const secret = (parsedUrl.searchParams.get('secret') || '').replace(/[\s-]/g, '');
    if (!secret) return null;
    let issuer = (parsedUrl.searchParams.get('issuer') || '').trim();
    let name = label;
    const colonIndex = label.indexOf(':');
    if (colonIndex >= 0) {
      const labelIssuer = label.slice(0, colonIndex).trim();
      const labelName = label.slice(colonIndex + 1).trim();
      if (!issuer && labelIssuer) issuer = labelIssuer;
      name = labelName || labelIssuer;
    }
    return {
      name: name || '未命名',
      secret,
      issuer,
    };
  } catch (_) {
    return null;
  }
}

function parseUrls(text) {
  return Array.from(new Set(
    String(text || '').split(/[\n,]+/).map(function(item) {
      return item.trim().toLowerCase();
    }).filter(Boolean)
  ));
}

function normalizeUrlForDisplay(url) {
  const value = String(url || '').trim().toLowerCase();
  if (!value) return '';
  try {
    const parsedUrl = new URL(value.startsWith('http') ? value : 'https://' + value);
    const hasPath = parsedUrl.pathname && parsedUrl.pathname !== '/';
    if (hasPath) return parsedUrl.origin + parsedUrl.pathname.replace(/\/$/, '');
    return parsedUrl.hostname;
  } catch (_) {
    return value;
  }
}

function isValidBase32(secret) {
  const normalized = String(secret || '').replace(/\s/g, '').toUpperCase();
  return /^[A-Z2-7]+=*$/.test(normalized) && normalized.length >= 16;
}

function maskSecret(secret) {
  const normalized = String(secret || '').replace(/\s/g, '');
  if (normalized.length <= 8) return normalized;
  return normalized.slice(0, 4) + '...' + normalized.slice(-4);
}

function renderList(entries) {
  const list = document.getElementById('entries-list');
  list.innerHTML = '';
  if (!entries.length) {
    list.innerHTML = '<li class="entry-item" style="color:#888;">暂无密钥，请在上方导入。</li>';
    return;
  }

  entries.forEach(function(entry) {
    const li = document.createElement('li');
    li.className = 'entry-item';
    const urls = (entry.urls || []).join('\n');
    const note = entry.note || '';
    li.innerHTML = `
      <div class="entry-info">
        <div class="name">${escapeHtml(entry.name)}</div>
        ${entry.issuer ? `<div class="issuer">${escapeHtml(entry.issuer)}</div>` : ''}
        <div class="issuer">密钥：${escapeHtml(maskSecret(entry.secret))}</div>
        <div class="note-row">
          <label class="note-label">备注/名称</label>
          <input class="entry-note" type="text" placeholder="例如：主号 / 测试环境" value="${escapeHtml(note)}">
          <button type="button" class="btn-save-note">保存备注</button>
        </div>
        <div class="urls-row">
          <label class="urls-label">适用地址（域名或完整 URL 路径，每行一个；填完整路径可只在动码页填入）</label>
          <textarea class="entry-urls" rows="2" placeholder="例如：github.com 或 https://domain/index/login/advanced">${escapeHtml(urls)}</textarea>
          <button type="button" class="btn-save-urls">保存地址</button>
        </div>
      </div>
      <div class="entry-actions">
        <button type="button" class="danger" data-id="${escapeHtml(entry.id)}">删除</button>
      </div>
    `;

    li.querySelector('.danger').addEventListener('click', function() {
      removeEntry(entry.id);
    });

    li.querySelector('.btn-save-urls').addEventListener('click', async function() {
      const text = li.querySelector('.entry-urls').value;
      const normalized = parseUrls(text).map(normalizeUrlForDisplay);
      const currentEntries = await getStorage();
      const index = currentEntries.findIndex(function(item) {
        return item.id === entry.id;
      });
      if (index !== -1) {
        currentEntries[index].urls = normalized;
        await setStorage(currentEntries);
        showMessage(document.querySelector('.list-section'), '已保存适用地址', 'success');
      }
    });

    li.querySelector('.btn-save-note').addEventListener('click', async function() {
      const text = li.querySelector('.entry-note').value.trim();
      const currentEntries = await getStorage();
      const index = currentEntries.findIndex(function(item) {
        return item.id === entry.id;
      });
      if (index !== -1) {
        currentEntries[index].note = text;
        await setStorage(currentEntries);
        showMessage(document.querySelector('.list-section'), '已保存备注', 'success');
      }
    });

    list.appendChild(li);
  });
}

async function removeEntry(id) {
  const entries = await getStorage();
  const next = entries.filter(function(entry) {
    return entry.id !== id;
  });
  await setStorage(next);
  renderList(next);
}

async function addEntry(entry) {
  const entries = await getStorage();
  const urls = entry.urls ? parseUrls(entry.urls) : [];
  entries.push({
    id: generateEntryId(),
    name: entry.name,
    secret: entry.secret,
    issuer: entry.issuer || '',
    note: entry.note || '',
    urls: urls.map(normalizeUrlForDisplay),
  });
  await setStorage(entries);
  renderList(entries);
}

async function importFromOtpauth() {
  const input = document.getElementById('otpauth-input');
  const parsed = parseOtpauth(input.value);
  if (!parsed) {
    showMessage(document.querySelector('.import-section'), '无效的 otpauth 链接', 'error');
    return;
  }
  if (!isValidBase32(parsed.secret)) {
    showMessage(document.querySelector('.import-section'), '密钥格式错误（需为 Base32）', 'error');
    return;
  }
  const urlsField = document.getElementById('otpauth-urls');
  const noteField = document.getElementById('otpauth-note');
  const urlsText = urlsField ? urlsField.value.trim() : '';
  const noteText = noteField ? noteField.value.trim() : '';
  await addEntry({
    name: parsed.name,
    secret: parsed.secret,
    issuer: parsed.issuer,
    note: noteText,
    urls: urlsText
  });
  input.value = '';
  if (urlsField) urlsField.value = '';
  if (noteField) noteField.value = '';
  showMessage(document.querySelector('.import-section'), '已添加：' + parsed.name, 'success');
}

async function decodeQrFromFile(file) {
  if (!file) return null;
  if (typeof BarcodeDetector === 'undefined') {
    throw new Error('当前浏览器不支持二维码识别');
  }
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  let bitmap;
  try {
    if (typeof createImageBitmap === 'function') {
      bitmap = await createImageBitmap(file);
      const codes = await detector.detect(bitmap);
      if (!codes || codes.length === 0) return null;
      const values = codes.map((item) => item.rawValue).filter(Boolean);
      return values.find((value) => /^otpauth:\/\//i.test(value)) || values[0] || null;
    }
  } finally {
    if (bitmap && typeof bitmap.close === 'function') {
      bitmap.close();
    }
  }

  const dataUrl = await new Promise(function(resolve, reject) {
    const reader = new FileReader();
    reader.onload = function() { resolve(reader.result); };
    reader.onerror = function() { reject(new Error('读取图片失败')); };
    reader.readAsDataURL(file);
  });
  const img = new Image();
  img.src = dataUrl;
  await new Promise(function(resolve, reject) {
    img.onload = resolve;
    img.onerror = function() { reject(new Error('加载图片失败')); };
  });
  const codes = await detector.detect(img);
  if (!codes || codes.length === 0) return null;
  const values = codes.map((item) => item.rawValue).filter(Boolean);
  return values.find((value) => /^otpauth:\/\//i.test(value)) || values[0] || null;
}

async function importFromQr() {
  const fileInput = document.getElementById('qr-file');
  const urlsField = document.getElementById('qr-urls');
  const noteField = document.getElementById('qr-note');
  const file = fileInput && fileInput.files ? fileInput.files[0] : null;
  if (!file) {
    showMessage(document.querySelector('.import-section'), '请先选择二维码图片', 'error');
    return;
  }
  let rawValue;
  try {
    rawValue = await decodeQrFromFile(file);
  } catch (err) {
    showMessage(document.querySelector('.import-section'), err.message || '识别失败', 'error');
    return;
  }
  if (!rawValue) {
    showMessage(document.querySelector('.import-section'), '未识别到二维码内容', 'error');
    return;
  }
  const parsed = parseOtpauth(rawValue);
  if (!parsed) {
    showMessage(document.querySelector('.import-section'), '二维码内容不是有效的 otpauth 链接', 'error');
    return;
  }
  if (!isValidBase32(parsed.secret)) {
    showMessage(document.querySelector('.import-section'), '密钥格式错误（需为 Base32）', 'error');
    return;
  }
  const urlsText = urlsField ? urlsField.value.trim() : '';
  const noteText = noteField ? noteField.value.trim() : '';
  await addEntry({
    name: parsed.name,
    secret: parsed.secret,
    issuer: parsed.issuer,
    note: noteText,
    urls: urlsText
  });
  if (fileInput) fileInput.value = '';
  if (urlsField) urlsField.value = '';
  if (noteField) noteField.value = '';
  showMessage(document.querySelector('.import-section'), '已添加：' + parsed.name, 'success');
}

async function importManual() {
  const nameField = document.getElementById('manual-name');
  const secretField = document.getElementById('manual-secret');
  const issuerField = document.getElementById('manual-issuer');
  const noteField = document.getElementById('manual-note');
  const urlsField = document.getElementById('manual-urls');
  const name = nameField.value.trim();
  const secret = secretField.value.trim().replace(/\s/g, '');
  const issuer = issuerField.value.trim();
  const note = noteField ? noteField.value.trim() : '';
  if (!name || !secret) {
    showMessage(document.querySelector('.import-section'), '请填写账户名和密钥', 'error');
    return;
  }
  if (!isValidBase32(secret)) {
    showMessage(document.querySelector('.import-section'), '密钥格式错误（需为 Base32）', 'error');
    return;
  }
  await addEntry({
    name: name,
    secret: secret,
    issuer: issuer,
    note: note,
    urls: urlsField ? urlsField.value.trim() : ''
  });
  nameField.value = '';
  secretField.value = '';
  issuerField.value = '';
  if (noteField) noteField.value = '';
  if (urlsField) urlsField.value = '';
  showMessage(document.querySelector('.import-section'), '已添加：' + name, 'success');
}

function initTabs() {
  const buttons = Array.from(document.querySelectorAll('.tab-button'));
  const panels = Array.from(document.querySelectorAll('.tab-panel'));
  if (!buttons.length || !panels.length) return;
  buttons.forEach(function(button) {
    button.addEventListener('click', function() {
      const targetId = button.getAttribute('data-tab');
      buttons.forEach(function(btn) {
        const isActive = btn === button;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-selected', String(isActive));
      });
      panels.forEach(function(panel) {
        panel.classList.toggle('active', panel.id === targetId);
      });
    });
  });
}

function initOptionsPage() {
  const importOtpauthButton = document.getElementById('btn-import-otpauth');
  const importManualButton = document.getElementById('btn-import-manual');
  const importQrButton = document.getElementById('btn-import-qr');
  if (!importOtpauthButton || !importManualButton || !importQrButton) {
    showFatalMessage('设置页初始化失败，请重新打开。');
    return;
  }

  initTabs();
  importOtpauthButton.addEventListener('click', importFromOtpauth);
  importManualButton.addEventListener('click', importManual);
  importQrButton.addEventListener('click', importFromQr);

  getStorage().then(renderList).catch(function() {
    showFatalMessage('加载失败，请刷新。');
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initOptionsPage, { once: true });
} else {
  initOptionsPage();
}
