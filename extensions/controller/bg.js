const UBLOCK_ID = 'kggmfbbahicjjengfajhfpggdcdphfkl';
const HELIUM_STUB_UBLOCK_ID = 'blockjmkbacgjkknlgpkjjiijinjdanf';
const VPN_ID = 'flokmmfhjhogkkadaahlidjlbilkabme';

async function applyInitState() {
  try {
    const res = await fetch(chrome.runtime.getURL('init_state.json'), { cache: 'no-store' });
    const cfg = await res.json();
    await chrome.storage.local.set({ hermesInitCfg: cfg });

    const exts = await chrome.management.getAll();
    for (const ext of exts) {
      if (ext.id === HELIUM_STUB_UBLOCK_ID) {
        if (ext.enabled) {
          try { await chrome.management.setEnabled(ext.id, false); } catch (e) {}
        }
        continue;
      }
      if (ext.id === UBLOCK_ID) {
        if (!ext.enabled) {
          try { await chrome.management.setEnabled(ext.id, true); } catch (e) {}
        }
      }
      if (ext.id === VPN_ID || ext.name.toLowerCase().includes('1click') || ext.name.toLowerCase().includes('vpn')) {
        if (typeof cfg.vpn === 'boolean' && ext.enabled !== cfg.vpn) {
          await chrome.management.setEnabled(ext.id, cfg.vpn);
        }
      }
    }
  } catch (e) {
    console.error('HermesBox init state error:', e);
  }
}

chrome.management.onDisabled.addListener(async (info) => {
  if (info.id === UBLOCK_ID) {
    try {
      await chrome.management.setEnabled(info.id, true);
    } catch (e) {}
  }
});

applyInitState();
chrome.runtime.onStartup.addListener(applyInitState);
chrome.runtime.onInstalled.addListener(applyInitState);
