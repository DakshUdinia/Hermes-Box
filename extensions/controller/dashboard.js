const UBLOCK_ID = 'kggmfbbahicjjengfajhfpggdcdphfkl';
const VPN_ID = 'flokmmfhjhogkkadaahlidjlbilkabme';

let ubExt = null;
let vpnExt = null;

async function refreshExtensions() {
  const exts = await chrome.management.getAll();
  ubExt = exts.find(e => e.id === UBLOCK_ID);
  vpnExt = exts.find(e => e.id === VPN_ID) || exts.find(e => e.name.toLowerCase().includes('1click') || e.name.toLowerCase().includes('vpn'));

  const ubStatus = document.getElementById('ubStatus');
  const ubToggle = document.getElementById('ubToggle');
  if (ubExt) {
    if (!ubExt.enabled) {
      try { await chrome.management.setEnabled(ubExt.id, true); ubExt.enabled = true; } catch (e) {}
    }
    ubStatus.textContent = 'ACTIVE — Always-On Ad & Tracker Shield';
    ubToggle.textContent = 'ALWAYS ON';
    ubToggle.className = 'switch on';
    ubToggle.style.cursor = 'default';
  } else {
    ubStatus.textContent = 'Active (Built-in)';
  }

  const vpnStatus = document.getElementById('vpnStatus');
  const vpnToggle = document.getElementById('vpnToggle');
  if (vpnExt) {
    vpnStatus.textContent = vpnExt.enabled ? 'ENABLED — Ready on top-right toolbar' : 'DISABLED — Direct connection';
    vpnToggle.textContent = vpnExt.enabled ? 'ON (Disable)' : 'OFF (Enable)';
    vpnToggle.className = 'switch ' + (vpnExt.enabled ? 'on' : 'off');
  } else {
    vpnStatus.textContent = 'Not found';
  }
}

document.getElementById('vpnToggle').addEventListener('click', async () => {
  if (!vpnExt) return;
  await chrome.management.setEnabled(vpnExt.id, !vpnExt.enabled);
  await refreshExtensions();
});

document.getElementById('searchForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const raw = document.getElementById('urlInput').value.trim();
  if (!raw) return;
  let target = raw;
  if (!/^https?:\/\//i.test(raw) && !/^chrome:\/\//i.test(raw)) {
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/.*)?$/i.test(raw)) {
      target = 'https://' + raw;
    } else {
      target = 'https://duckduckgo.com/?q=' + encodeURIComponent(raw);
    }
  }
  window.location.href = target;
});

document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => chip.classList.toggle('selected'));
});

document.getElementById('openSelectedBtn').addEventListener('click', async () => {
  const urls = [];
  document.querySelectorAll('.chip.selected').forEach(c => {
    urls.push(c.getAttribute('data-url'));
    c.classList.remove('selected');
  });
  const extra = document.getElementById('multiUrls').value
    .split(/[\r\n,]+/)
    .map(s => s.trim())
    .filter(Boolean);
  for (const u of extra) {
    urls.push(/^https?:\/\//i.test(u) ? u : 'https://' + u);
  }
  document.getElementById('multiUrls').value = '';
  for (const u of urls) {
    await chrome.tabs.create({ url: u, active: true });
  }
  updateTabCount();
});

async function updateTabCount() {
  const tabs = await chrome.tabs.query({});
  const el = document.getElementById('tabCountInfo');
  if (el) el.textContent = `Open tabs in sandbox: ${tabs.length}`;
}

document.getElementById('cleanTabsBtn').addEventListener('click', async () => {
  const cur = await chrome.tabs.getCurrent();
  const tabs = await chrome.tabs.query({});
  const toClose = tabs.filter(t => cur && t.id !== cur.id).map(t => t.id);
  if (toClose.length > 0) await chrome.tabs.remove(toClose);
  updateTabCount();
});

document.getElementById('panicBtn').addEventListener('click', async () => {
  const wins = await chrome.windows.getAll();
  for (const w of wins) {
    await chrome.windows.remove(w.id);
  }
});

chrome.storage.local.get(['hermesInitCfg'], (res) => {
  if (res && res.hermesInitCfg) {
    const c = res.hermesInitCfg;
    if (c.mode) document.getElementById('modeBadge').textContent = c.mode;
    if (c.cap) document.getElementById('capBadge').textContent = c.cap;
  }
});

refreshExtensions();
updateTabCount();
chrome.tabs.onCreated.addListener(updateTabCount);
chrome.tabs.onRemoved.addListener(updateTabCount);
