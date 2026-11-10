const HOST_NAME = 'com.hermesbox.bridge';

function setupMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'hermesbox-link',
      title: '🛡️ Open Link in Hermes Box Sandbox',
      contexts: ['link']
    });
    chrome.contextMenus.create({
      id: 'hermesbox-page',
      title: '🛡️ Move This Tab to Hermes Box Sandbox',
      contexts: ['page']
    });
  });
}

chrome.runtime.onInstalled.addListener(setupMenus);
chrome.runtime.onStartup.addListener(setupMenus);

function launchInSandbox(urls, ublock = true, vpn = true) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(
        HOST_NAME,
        { urls, ublock, vpn },
        (response) => {
          if (chrome.runtime.lastError) {
            console.warn('Native messaging fallback:', chrome.runtime.lastError.message);
            resolve({ ok: false, error: chrome.runtime.lastError.message });
          } else {
            resolve(response || { ok: true });
          }
        }
      );
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const saved = await chrome.storage.local.get(['ublock', 'vpn']);
  const ublock = saved.ublock !== false;
  const vpn = saved.vpn !== false;

  if (info.menuItemId === 'hermesbox-link' && info.linkUrl) {
    await launchInSandbox([info.linkUrl], ublock, vpn);
  } else if (info.menuItemId === 'hermesbox-page' && tab && tab.url) {
    await launchInSandbox([tab.url], ublock, vpn);
    if (tab.id) {
      const allTabs = await chrome.tabs.query({ currentWindow: true });
      if (allTabs.length > 1) chrome.tabs.remove(tab.id);
    }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'LAUNCH_SANDBOX') {
    launchInSandbox(msg.urls || [], msg.ublock !== false, msg.vpn !== false).then(sendResponse);
    return true;
  }
  if (msg && msg.type === 'OPEN_GUI') {
    try {
      chrome.runtime.sendNativeMessage(HOST_NAME, { mode: 'gui' }, (res) => {
        sendResponse(res || { ok: true });
      });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
    return true;
  }
});
