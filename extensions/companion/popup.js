let currentTabs = [];

function updateCount() {
  const checked = document.querySelectorAll('.tab-cb:checked').length;
  document.getElementById('selCount').textContent = `${checked} selected`;
}

async function loadTabs() {
  const listEl = document.getElementById('tabList');
  listEl.innerHTML = '';
  currentTabs = await chrome.tabs.query({ currentWindow: true });

  for (const t of currentTabs) {
    const row = document.createElement('label');
    row.className = 'tab-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'tab-cb';
    cb.dataset.tabId = t.id;
    cb.dataset.url = t.url || '';
    if (t.active) cb.checked = true;
    cb.addEventListener('change', updateCount);

    const span = document.createElement('span');
    span.className = 'tab-title';
    span.textContent = t.title || t.url || 'New Tab';
    span.title = t.url || '';

    row.appendChild(cb);
    row.appendChild(span);
    listEl.appendChild(row);
  }
  updateCount();

  const saved = await chrome.storage.local.get(['ublock', 'vpn', 'closeAfter']);
  if (typeof saved.ublock === 'boolean') document.getElementById('chkUblock').checked = saved.ublock;
  if (typeof saved.vpn === 'boolean') document.getElementById('chkVpn').checked = saved.vpn;
  if (typeof saved.closeAfter === 'boolean') document.getElementById('chkCloseAfter').checked = saved.closeAfter;
}

document.getElementById('selActive').addEventListener('click', () => {
  document.querySelectorAll('.tab-cb').forEach((cb, i) => {
    cb.checked = Boolean(currentTabs[i] && currentTabs[i].active);
  });
  updateCount();
});

document.getElementById('selAll').addEventListener('click', () => {
  document.querySelectorAll('.tab-cb').forEach(cb => { cb.checked = true; });
  updateCount();
});

document.getElementById('selNone').addEventListener('click', () => {
  document.querySelectorAll('.tab-cb').forEach(cb => { cb.checked = false; });
  updateCount();
});

async function savePrefs() {
  await chrome.storage.local.set({
    ublock: document.getElementById('chkUblock').checked,
    vpn: document.getElementById('chkVpn').checked,
    closeAfter: document.getElementById('chkCloseAfter').checked
  });
}

document.getElementById('chkUblock').addEventListener('change', savePrefs);
document.getElementById('chkVpn').addEventListener('change', savePrefs);
document.getElementById('chkCloseAfter').addEventListener('change', savePrefs);

async function triggerLaunch(urls, tabIdsToClose) {
  await savePrefs();
  const ublock = document.getElementById('chkUblock').checked;
  const vpn = document.getElementById('chkVpn').checked;
  const statusEl = document.getElementById('statusMsg');
  statusEl.textContent = 'Launching Hermes Box Sandbox...';

  chrome.runtime.sendMessage(
    { type: 'LAUNCH_SANDBOX', urls, ublock, vpn },
    async (res) => {
      if (res && res.ok) {
        statusEl.textContent = 'Sandbox launched!';
        if (tabIdsToClose && tabIdsToClose.length > 0) {
          const all = await chrome.tabs.query({ currentWindow: true });
          if (tabIdsToClose.length >= all.length) {
            await chrome.tabs.create({});
          }
          await chrome.tabs.remove(tabIdsToClose);
        }
        setTimeout(() => window.close(), 450);
      } else {
        statusEl.style.color = '#f59e0b';
        statusEl.textContent = (res && res.error) ? res.error : 'Triggered via bridge';
      }
    }
  );
}

document.getElementById('launchSelBtn').addEventListener('click', () => {
  const urls = [];
  const ids = [];
  document.querySelectorAll('.tab-cb:checked').forEach(cb => {
    const u = cb.dataset.url;
    if (u && /^https?:\/\//i.test(u)) urls.push(u);
    ids.push(Number(cb.dataset.tabId));
  });
  const closeAfter = document.getElementById('chkCloseAfter').checked;
  triggerLaunch(urls, closeAfter ? ids : []);
});

document.getElementById('launchBlankBtn').addEventListener('click', () => {
  triggerLaunch([], []);
});

document.getElementById('openGuiBtn').addEventListener('click', () => {
  const statusEl = document.getElementById('statusMsg');
  statusEl.textContent = 'Opening Hermes Box Control Center...';
  chrome.runtime.sendMessage({ type: 'OPEN_GUI' }, () => {
    setTimeout(() => window.close(), 350);
  });
});

loadTabs();
