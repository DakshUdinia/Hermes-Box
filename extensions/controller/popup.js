const UBLOCK_ID = 'kggmfbbahicjjengfajhfpggdcdphfkl';
const VPN_ID = 'flokmmfhjhogkkadaahlidjlbilkabme';

let ubExt = null;
let vpnExt = null;

async function sync() {
  const exts = await chrome.management.getAll();
  ubExt = exts.find(e => e.id === UBLOCK_ID);
  vpnExt = exts.find(e => e.id === VPN_ID) || exts.find(e => e.name.toLowerCase().includes('1click') || e.name.toLowerCase().includes('vpn'));

  const ubBtn = document.getElementById('ubBtn');
  const ubSub = document.getElementById('ubSub');
  if (ubExt) {
    if (!ubExt.enabled) {
      try { await chrome.management.setEnabled(ubExt.id, true); ubExt.enabled = true; } catch (e) {}
    }
    ubBtn.textContent = 'ALWAYS ON';
    ubBtn.className = 'on';
    ubSub.textContent = 'Active & Locked On';
  }

  const vpnBtn = document.getElementById('vpnBtn');
  const vpnSub = document.getElementById('vpnSub');
  if (vpnExt) {
    vpnBtn.textContent = vpnExt.enabled ? 'ON' : 'OFF';
    vpnBtn.className = vpnExt.enabled ? 'on' : 'off';
    vpnSub.textContent = vpnExt.enabled ? 'Enabled (Click VPN icon to connect)' : 'Disabled';
  }
}

document.getElementById('vpnBtn').addEventListener('click', async () => {
  if (!vpnExt) return;
  await chrome.management.setEnabled(vpnExt.id, !vpnExt.enabled);
  sync();
});

document.getElementById('dashBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: 'chrome://newtab' });
  window.close();
});

document.getElementById('panicBtn').addEventListener('click', async () => {
  const wins = await chrome.windows.getAll();
  for (const w of wins) await chrome.windows.remove(w.id);
});

sync();
