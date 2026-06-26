// content.js - показывает уведомления только после авторизации

let notificationShown = false;
let isAuthorized = false;
console.log('🔴 ТЕСТ: content.js загружен на этой странице');
// Проверяем, авторизован ли пользователь
async function checkAuthorization() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['token', 'user'], (result) => {
      if (result.token && result.user) {
        isAuthorized = true;
        console.log('✅ Пользователь авторизован, уведомления включены');
        resolve(true);
      } else {
        isAuthorized = false;
        console.log('⏳ Ожидание авторизации...');
        resolve(false);
      }
    });
  });
}

// Ждём авторизации (проверяем каждую секунду)
async function waitForAuth() {
  while (true) {
    const authorized = await checkAuthorization();
    if (authorized) return true;
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

function showWarning(result) {
  // Показываем уведомления только если авторизован
  if (!isAuthorized) {
    console.log('🔇 Пропускаем уведомление: нет авторизации');
    return;
  }
  
//  if (notificationShown) return;
  if (document.getElementById('antiphishing-warning')) return;
  
  notificationShown = true;
  
  const warningDiv = document.createElement('div');
  warningDiv.id = 'antiphishing-warning';
  
  let backgroundColor, iconSvg, title, message, borderColor;
  
  if (result.isWhitelisted) {
    backgroundColor = '#10b981';
    iconSvg = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
        <path d="M8 12L11 15L16 9" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
    title = 'Безопасный сайт';
    message = result.details || 'Сайт в белом списке безопасных ресурсов';
    borderColor = '#34d399';
  } 
  else if (result.verdict === 'phishing' || result.isPhishing === true) {
    backgroundColor = '#ef4444';
    iconSvg = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
        <path d="M12 8V12M12 16H12.01" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
      </svg>
    `;
    title = 'ФИШИНГОВЫЙ САЙТ!';
    message = 'ВНИМАНИЕ! НЕ ВВОДИТЕ ЛИЧНЫЕ ДАННЫЕ!';
    borderColor = '#f87171';
    addPhishingOverlay(result.reason || result.details);
  } 
  else if (result.verdict === 'safe' || result.riskLevel === 'safe') {
    backgroundColor = '#10b981';
    iconSvg = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
        <path d="M8 12L11 15L16 9" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
    title = 'Сайт безопасен';
    message = 'Сайт прошел проверку и признан безопасным';
    borderColor = '#34d399';
  } 
  else if (result.verdict === 'error' || result.riskLevel === 'error') {
    backgroundColor = '#f59e0b';
    iconSvg = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
        <path d="M8 8L16 16M16 8L8 16" stroke="white" stroke-width="2" stroke-linecap="round"/>
      </svg>
    `;
    title = 'Ошибка проверки';
    message = result.reason || result.details || 'Не удалось подключиться к серверу проверки';
    borderColor = '#fbbf24';
  } 
  else {
    backgroundColor = '#6b7280';
    iconSvg = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
        <path d="M12 8V12M12 16H12.01" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
      </svg>
    `;
    title = 'Результат проверки';
    message = result.details || result.reason || 'Сайт проверен';
    borderColor = '#9ca3af';
  }
  
  if (result.confidence && result.verdict !== 'error' && result.verdict !== 'phishing') {
    message ;
  }
  
  warningDiv.innerHTML = `
    <div style="
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 10000;
      background: ${backgroundColor};
      color: white;
      padding: 16px 20px;
      border-radius: 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      font-weight: 500;
      box-shadow: 0 8px 32px rgba(0,0,0,0.25);
      cursor: pointer;
      backdrop-filter: blur(10px);
      animation: slideInRight 0.3s ease;
      max-width: 400px;
      border-left: 4px solid ${borderColor};
    ">
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <div style="flex-shrink: 0;">${iconSvg}</div>
        <div style="flex: 1;">
          <div style="font-weight: 800; margin-bottom: 6px; font-size: 16px;">${title}</div>
          <div style="font-size: 12px; opacity: 0.95; line-height: 1.4;">${message}</div>
        </div>
        <span style="font-size: 18px; cursor: pointer; opacity: 0.7;">✖</span>
      </div>
    </div>
    <style>
      @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
      }
    </style>
  `;
  
  document.body.appendChild(warningDiv);
  
  const closeBtn = warningDiv.querySelector('span:last-child');
  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      warningDiv.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => warningDiv.remove(), 300);
    });
  }
  
  warningDiv.addEventListener('click', (e) => {
    if (e.target !== closeBtn && !closeBtn?.contains(e.target)) {
      warningDiv.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => warningDiv.remove(), 300);
    }
  });
  
  if (result.verdict !== 'phishing' && !result.isPhishing) {
    setTimeout(() => {
      if (warningDiv.parentNode) {
        warningDiv.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => warningDiv.remove(), 300);
      }
    }, 8000);
  }
}

function addPhishingOverlay(reason) {
  if (document.getElementById('phishing-overlay')) return;
  
  const overlay = document.createElement('div');
  overlay.id = 'phishing-overlay';
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.95);
      z-index: 9999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: fadeIn 0.3s ease;
    ">
      <div style="
        background: linear-gradient(135deg, #ef4444, #dc2626);
        color: white;
        padding: 32px 40px;
        border-radius: 24px;
        text-align: center;
        max-width: 550px;
        margin: 20px;
        box-shadow: 0 25px 50px rgba(0,0,0,0.4);
        animation: scaleIn 0.3s ease;
      ">
        <div style="margin-bottom: 20px;">
          <svg width="72" height="72" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="10" stroke="white" stroke-width="2"/>
            <path d="M12 8V12M12 16H12.01" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
          </svg>
        </div>
        <h2 style="margin-bottom: 16px; font-size: 28px; font-weight: 800;">ФИШИНГОВЫЙ САЙТ!</h2>
        <p style="margin-bottom: 16px; line-height: 1.6; font-size: 16px;">
          ⚠️ Этот сайт определён как фишинговый.
        </p>
        <p style="margin-bottom: 24px; line-height: 1.5; font-size: 14px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 12px;">
          📍 ${reason || 'Ввод личных данных, паролей или банковской информации может привести к краже ваших данных!'}
        </p>
        <div style="display: flex; gap: 12px; justify-content: center;">
                    <button id="leave-site-btn" style="background: rgba(255,255,255,0.2); color: white; border: 2px solid white; padding: 12px 28px; border-radius: 40px; font-size: 14px; font-weight: 700; cursor: pointer;">Покинуть сайт</button>
        </div>
      </div>
    </div>
    <style>
      @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      @keyframes scaleIn { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }
      @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }
    </style>
  `;
  
  document.body.appendChild(overlay);
  
  //document.getElementById('close-overlay-btn')?.addEventListener('click', () //=> {
//    overlay.style.animation = 'fadeOut 0.3s ease';
//    setTimeout(() => overlay.remove(), 300);
//  });
  
  document.getElementById('leave-site-btn')?.addEventListener('click', () => {
    window.location.href = 'https://www.google.com';
  });
}

function waitForBody() {
  return new Promise((resolve) => {
    if (document.body) {
      resolve();
    } else {
      const observer = new MutationObserver(() => {
        if (document.body) {
          observer.disconnect();
          resolve();
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  });
}

async function checkAndNotify() {
  const currentUrl = window.location.href;
  
  if (currentUrl.startsWith('chrome://') || 
      currentUrl.startsWith('chrome-extension://') ||
      currentUrl.startsWith('about:') ||
      currentUrl.startsWith('edge://')) {
    console.log('Системная страница, пропускаем проверку');
    return;
  }
  
  // Ждём авторизации перед первой проверкой
  if (!isAuthorized) {
    console.log('⏳ Ожидание авторизации...');
    await waitForAuth();
  }
  
  console.log('🔍 Content Script: Проверка URL', currentUrl);
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'CHECK_URL', url: currentUrl });
    
    if (response && response.success && response.result) {
      console.log('✅ Результат проверки:', response.result);
	await chrome.storage.local.set({ lastCheckResult: response.result });
      await waitForBody();
      
      // УДАЛЯЕМ СТАРОЕ УВЕДОМЛЕНИЕ (если есть)
      const oldWarning = document.getElementById('antiphishing-warning');
      if (oldWarning) oldWarning.remove();
      
      // ПОКАЗЫВАЕМ НОВОЕ УВЕДОМЛЕНИЕ
      showWarning(response.result);
    } else {
      console.error('❌ Ошибка проверки:', response?.error);
    }
  } catch (error) {
    console.error('❌ Ошибка:', error);
  }
}
// Запускаем проверку только после загрузки страницы и авторизации
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    waitForAuth().then(() => {
      checkAndNotify();
    });
  });
} else {
  waitForAuth().then(() => {
    checkAndNotify();
  });
}
// При переключении на вкладку — повторно проверяем
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    console.log('👁️ Вкладка стала активной, повторная проверка');
    // Удаляем старое уведомление
    const oldWarning = document.getElementById('antiphishing-warning');
    if (oldWarning) oldWarning.remove();
    // Сбрасываем флаг
    notificationShown = false;
    // Запускаем проверку
    waitForAuth().then(() => {
      setTimeout(checkAndNotify, 500);
    });
  }
});

// Следим за изменением URL (для SPA)
let lastUrl = location.href;
new MutationObserver(() => {
  const url = location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    notificationShown = false;
    waitForAuth().then(() => {
      setTimeout(checkAndNotify, 500);
    });
  }
}).observe(document, { subtree: true, childList: true });