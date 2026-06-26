// popup.js - Полностью рабочая версия
const API_BASE = 'http://127.0.0.1:8000';
let currentTabUrl = '';
let currentUser = null;
let isAuthRequired = false;
let lastCheckResult = null;
function debug(message) {
  const debugEl = document.getElementById('debugInfo');
  if (debugEl) {
    const time = new Date().toLocaleTimeString();
    debugEl.textContent = `📡 [${time}] ${message}`;
  }
  console.log(`[Popup] ${message}`);
}

function showNotification(message) {
  const old = document.querySelector('.copy-notification');
  if (old) old.remove();
  const notif = document.createElement('div');
  notif.className = 'copy-notification';
  notif.textContent = message;
  document.body.appendChild(notif);
  setTimeout(() => notif.remove(), 2000);
}

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  console.log('Tab from query:', tab);
  if (tab && tab.url) {
    console.log('URL получен:', tab.url);
    return tab;
  }
  console.warn('Не удалось получить URL');
  return null;
}


async function loadRemainingChecks() {
  // Не загружаем лимит, если пользователь не авторизован
  if (isAuthRequired) {
    const remainingEl = document.getElementById('remainingChecks');
    if (remainingEl) remainingEl.textContent = '—';
    return;
  }
  
  const remainingEl = document.getElementById('remainingChecks');
  
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_REMAINING_CHECKS' });
    if (response && remainingEl) {
      remainingEl.textContent = response.remaining;
      const upgradeLink = document.getElementById('upgradeLimitLink');
      if (response.remaining === 0 || response.remaining === '0') {
        remainingEl.style.color = '#ef4444';
        if (upgradeLink) upgradeLink.style.display = 'inline';
      } else {
        remainingEl.style.color = '#3b82f6';
        if (upgradeLink) upgradeLink.style.display = 'none';
      }
    }
  } catch (error) {
    debug(`Ошибка загрузки лимита: ${error.message}`);
  }
}

async function checkAuthStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'CHECK_AUTH' });
    
    const proBadge = document.getElementById('proBadge');
    const upgradeBtn = document.getElementById('upgradeBtn');
    const profileBtn = document.getElementById('profileBtn');
    const authRequiredDiv = document.getElementById('authRequired');
    const statusSection = document.getElementById('statusSection');
    const limitCard = document.querySelector('.limit-card');
    const recheckBtn = document.getElementById('recheckBtn');
    
    if (response.isLoggedIn) {
      currentUser = response.user;
      isAuthRequired = false;
      
      // Получаем свежие данные с сервера
      const token = (await chrome.storage.local.get('token')).token;
      let userPlan = currentUser.plan;
      
      if (token) {
        try {
          const userInfoResponse = await fetch(`${API_BASE}/api/user-info`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const userData = await userInfoResponse.json();
          userPlan = userData.is_premium ? 'pro' : 'free';
          currentUser.plan = userPlan;
          await chrome.storage.local.set({ user: currentUser });
        } catch (e) {
          console.warn('Не удалось получить user-info', e);
        }
      }
      
      debug(`Пользователь: ${currentUser.email} (${userPlan})`);
      
      // ПОКАЗЫВАЕМ
      if (limitCard) limitCard.style.display = 'flex';
      if (recheckBtn) recheckBtn.style.display = 'flex';
      if (statusSection) statusSection.style.display = 'block';
      if (authRequiredDiv) authRequiredDiv.style.display = 'none';
      
      if (userPlan === 'pro') {
        if (proBadge) proBadge.style.display = 'block';
        if (upgradeBtn) upgradeBtn.style.display = 'none';
        if (limitCard) limitCard.style.display = 'none';
 // Показать кнопку AI-проверки для PRO
    	const deepAnalyzeBtn = document.getElementById('deepAnalyzeBtn');
    	if (deepAnalyzeBtn) deepAnalyzeBtn.style.display = 'flex';
      } else {
        if (proBadge) proBadge.style.display = 'none';
        if (upgradeBtn) upgradeBtn.style.display = 'flex';
        if (limitCard) limitCard.style.display = 'flex';
	const deepAnalyzeBtn = document.getElementById('deepAnalyzeBtn');
        if (deepAnalyzeBtn) deepAnalyzeBtn.style.display = 'none';	
        }
      
      if (profileBtn) {
        const initial = currentUser.name ? currentUser.name[0].toUpperCase() : '👤';
        profileBtn.innerHTML = `<span style="font-size: 14px;">${initial}</span>`;
      }
      
    } else {
      currentUser = null;
      isAuthRequired = true;
      
      // СКРЫВАЕМ
	const deepAnalyzeBtn = document.getElementById('deepAnalyzeBtn');
    if (deepAnalyzeBtn) deepAnalyzeBtn.style.display = 'none';
      if (limitCard) limitCard.style.display = 'none';
      if (recheckBtn) recheckBtn.style.display = 'none';
      if (proBadge) proBadge.style.display = 'none';
      if (upgradeBtn) upgradeBtn.style.display = 'none';
      if (statusSection) statusSection.style.display = 'none';
      if (profileBtn) profileBtn.innerHTML = `<span>👤</span>`;
      if (authRequiredDiv) authRequiredDiv.style.display = 'block';
      
      debug('Пользователь не авторизован');
    }
  } catch (error) {
    debug(`Ошибка проверки авторизации: ${error.message}`);
  }
}
function updateStatusUI(result, isLoading = false) {
  const statusCard = document.getElementById('statusCard');
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const statusScore = document.getElementById('statusScore');
  const statusDesc = document.getElementById('statusDesc');
  
  if (!statusCard) return;
  
  if (isLoading) {
    statusCard.className = 'status-card loading';
    statusIcon.innerHTML = `
      <div class="pulsing-dots">
        <span></span><span></span><span></span>
      </div>
    `;
    statusText.textContent = 'ПРОВЕРКА...';
    statusScore.textContent = '';
    statusDesc.textContent = 'Отправка запроса на сервер';
    return;
  }
  
  if (!result) {
    statusCard.className = 'status-card error';
    statusIcon.innerHTML = `
      <svg class="error-icon" width="56" height="56" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle class="error-circle" cx="12" cy="12" r="10" stroke="#f59e0b" stroke-width="2"/>
        <path class="error-cross" d="M8 8L16 16M16 8L8 16" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
      </svg>
    `;
    statusText.textContent = 'ОШИБКА';
    statusScore.textContent = '';
    statusDesc.textContent = 'Не удалось проверить сайт';
    return;
  }
  
  if (result.needsAuth) {
  // Не показываем сообщение, просто скрываем статус
  statusCard.style.display = 'none';
  return;
}
  
  if (result.needsUpgrade) {
    statusCard.className = 'status-card error';
    statusIcon.innerHTML = `
      <svg class="error-icon" width="56" height="56" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle class="error-circle" cx="12" cy="12" r="10" stroke="#f59e0b" stroke-width="2"/>
        <path d="M12 8V12M12 16H12.01" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
        <path d="M3 3L21 21" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
      </svg>
    `;
    statusText.textContent = 'ЛИМИТ ИСЧЕРПАН';
    statusScore.textContent = '';
    statusDesc.textContent = result.details;
    return;
  }
  
  if (result.riskLevel === 'safe') {
    statusCard.className = 'status-card safe';
    statusIcon.innerHTML = `
      <div class="safe-icon-wrapper">
        <svg width="56" height="56" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle class="safe-circle" cx="12" cy="12" r="10" stroke="#10b981" stroke-width="2"/>
          <path class="safe-check-mark" d="M8 12L11 15L16 9" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div class="safe-pulse-ring"></div>
      </div>
    `;
    statusText.textContent = 'БЕЗОПАСНЫЙ';
    
    statusDesc.textContent = result.details || result.reason || 'Сайт безопасен';
  } 
  else if (result.riskLevel === 'phishing' || result.isPhishing) {
    statusCard.className = 'status-card phishing';
    statusIcon.innerHTML = `
      <div class="danger-icon-wrapper">
        <svg width="56" height="56" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="12" cy="12" r="10" stroke="#ef4444" stroke-width="2"/>
          <path class="danger-exclamation" d="M12 8V12M12 15H12.01" stroke="#ef4444" stroke-width="2" stroke-linecap="round"/>
        </svg>
        <div class="danger-pulse-ring"></div>
      </div>
    `;
    statusText.textContent = 'ФИШИНГ!';
    statusScore.textContent = `Опасность`;
    statusDesc.textContent = result.details || '⚠️ НЕ ВВОДИТЕ ЛИЧНЫЕ ДАННЫЕ!';
  } 
  else if (result.riskLevel === 'error') {
    statusCard.className = 'status-card error';
    statusIcon.innerHTML = `
      <svg class="error-icon" width="56" height="56" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle class="error-circle" cx="12" cy="12" r="10" stroke="#f59e0b" stroke-width="2"/>
        <path class="error-cross" d="M8 8L16 16M16 8L8 16" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
      </svg>
    `;
    statusText.textContent = 'ОШИБКА';
    statusScore.textContent = 'Сервер недоступен';
    statusDesc.textContent = result.details || 'Не удалось подключиться к серверу';
  }
}

async function checkUrl(url) {
  debug(`Проверка URL: ${url.substring(0, 60)}...`);
  
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { type: 'CHECK_URL', url: url },
      (response) => {
        if (chrome.runtime.lastError) {
          debug(`Ошибка: ${chrome.runtime.lastError.message}`);
          reject(new Error(chrome.runtime.lastError.message));
        } else if (response && response.success) {
          debug(`Результат: ${response.result.riskLevel}`);
          resolve(response.result);
        } else {
          debug(`Ошибка ответа: ${response?.error || 'Неизвестная ошибка'}`);
          reject(new Error(response?.error || 'Не удалось проверить сайт'));
        }
      }
    );
  });
}

async function checkCurrentSite() {
  if (!currentTabUrl) {
    debug('Нет URL для проверки');
    return;
  }
  
  if (isAuthRequired) {
    debug('Требуется авторизация');
    updateStatusUI({ needsAuth: true, details: 'Для проверки сайтов необходимо войти в аккаунт' }, false);
    return;
  }
  
  updateStatusUI(null, true);
  
  try {
    const result = await checkUrl(currentTabUrl);
    updateStatusUI(result, false);
    await loadRemainingChecks();
    debug(`Проверка завершена: ${result.riskLevel}`);
  } catch (error) {
    debug(`Ошибка проверки: ${error.message}`);
    updateStatusUI(null, false);
  }
}

function copyUrl() {
  if (currentTabUrl) {
    navigator.clipboard.writeText(currentTabUrl);
    showNotification('🔗 URL скопирован');
    debug('URL скопирован');
  }
}

function openAuthPanel() {
  chrome.windows.create({
    url: 'auth-panel.html',
    type: 'popup',
    width: 450,
    height: 620,
    focused: true
  });
}

function upgradeToPro() {
    chrome.tabs.create({ url: chrome.runtime.getURL('premium.html') });
}
async function init() {
  debug('Расширение загружено');
  
  await checkAuthStatus();

  await loadRemainingChecks();
  
  // Загружаем последний сохранённый результат проверки
  const stored = await chrome.storage.local.get('lastCheckResult');
  
  const tab = await getCurrentTab();
  
  if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('edge://')) {
    currentTabUrl = tab.url;
    const urlEl = document.getElementById('currentUrl');
    if (urlEl) {
      let displayUrl = tab.url;
      if (displayUrl.length > 70) displayUrl = displayUrl.substring(0, 67) + '...';
      urlEl.textContent = displayUrl;
      urlEl.title = tab.url;
    }
    
    if (isAuthRequired) {
      updateStatusUI({ needsAuth: true, details: 'Для проверки сайтов необходимо войти в аккаунт' }, false);
    } else if (stored.lastCheckResult) {
      // Показываем сохранённый результат
      lastCheckResult = stored.lastCheckResult;
      updateStatusUI(lastCheckResult, false);
    } else {
      // Нет сохранённого результата
      updateStatusUI(null, false);
      const statusText = document.getElementById('statusText');
      const statusDesc = document.getElementById('statusDesc');
      if (statusText) statusText.textContent = 'НЕ ПРОВЕРЕНО';
      if (statusDesc) statusDesc.textContent = 'Нажмите «Проверить» для анализа сайта';
    }
    
  } else if (tab && tab.url) {
    const urlEl = document.getElementById('currentUrl');
    if (urlEl) urlEl.textContent = 'Системная страница (не требует проверки)';
    if (!isAuthRequired) {
      updateStatusUI({ riskLevel: 'safe', details: 'Системная страница Chrome' }, false);
    }
    debug('Системная страница, проверка не требуется');
  } else {
    const urlEl = document.getElementById('currentUrl');
    if (urlEl) urlEl.textContent = 'Не удалось получить URL';
    debug('Не удалось получить URL');
  }
}
async function deepAnalyzeCurrentSite() {
    if (!currentTabUrl) {
        debug('Нет URL для AI-проверки');
        return;
    }
    
    if (isAuthRequired) {
        debug('Требуется авторизация');
        return;
    }
    
    updateStatusUI(null, true);
    
    try {
        const { token } = await chrome.storage.local.get('token');
        
        const response = await fetch('http://127.0.0.1:8000/api/deep-analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ url: currentTabUrl })
        });
        
        const result = await response.json();
        
        updateStatusUI({
            riskLevel: result.verdict === 'phishing' ? 'phishing' : (result.verdict === 'safe' ? 'safe' : 'error'),
            isPhishing: result.is_phishing,
            details: result.reason,
            reason: result.reason
        }, false);
        
        debug(`AI-проверка завершена: ${result.verdict}`);
        
    } catch (error) {
        debug(`AI-ошибка: ${error.message}`);
        updateStatusUI(null, false);
    }
}
function setupEventListeners() {
  const recheckBtn = document.getElementById('recheckBtn');
  const urlEl = document.getElementById('currentUrl');
  const profileBtn = document.getElementById('profileBtn');
  const upgradeBtn = document.getElementById('upgradeBtn');
  const upgradeLimitLink = document.getElementById('upgradeLimitLink');
  const openAuthBtn = document.getElementById('openAuthBtn');
  const deepAnalyzeBtn = document.getElementById('deepAnalyzeBtn');
if (deepAnalyzeBtn) {
    deepAnalyzeBtn.addEventListener('click', () => {
        debug('Нажата AI-проверка');
        deepAnalyzeCurrentSite();
    });
}
  if (recheckBtn) {
    recheckBtn.addEventListener('click', () => {
      debug('Ручная проверка');
      checkCurrentSite();
    });
  }
  
  
  if (urlEl) {
    urlEl.addEventListener('click', copyUrl);
  }
  
  if (profileBtn) {
    profileBtn.addEventListener('click', openAuthPanel);
  }
  
  if (upgradeBtn) {
    upgradeBtn.addEventListener('click', upgradeToPro);
  }
  
  if (upgradeLimitLink) {
    upgradeLimitLink.addEventListener('click', upgradeToPro);
  }
  
  if (openAuthBtn) {
    openAuthBtn.addEventListener('click', openAuthPanel);
  }
  
  const debugEl = document.getElementById('debugInfo');
  if (debugEl) {
    debugEl.addEventListener('click', () => {
      showNotification('🔄 Отладочная информация в консоли');
    });
  }
}
// Слушаем сообщения от background и auth-panel
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'USER_AUTH_CHANGED') {
    console.log('🔄 Получено событие USER_AUTH_CHANGED, обновляем UI');
    checkAuthStatus();

    loadRemainingChecks();
    
    // ПРИНУДИТЕЛЬНО ОБНОВЛЯЕМ ТЕКУЩИЙ URL
    (async () => {
      const tab = await getCurrentTab();
      if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('edge://')) {
        currentTabUrl = tab.url;
        const urlEl = document.getElementById('currentUrl');
        if (urlEl) {
          let displayUrl = tab.url;
          if (displayUrl.length > 70) displayUrl = displayUrl.substring(0, 67) + '...';
          urlEl.textContent = displayUrl;
          urlEl.title = tab.url;
        }
        await checkCurrentSite();
      }
    })();
    
    sendResponse({ success: true });
  }
  return true;
});document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  await init();
});