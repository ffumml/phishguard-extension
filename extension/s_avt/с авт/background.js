// background.js - Полная версия (твоя логика + серверная авторизация через JWT) без гостевого и чистый



// НОВОЕ: Базовые URL для API
const API_BASE = 'http://127.0.0.1:8000'; 
const API_ANALYZE_URL = `${API_BASE}/api/analyze`;
const API_LIMIT_URL = `${API_BASE}/api/check-limit`;
const API_TOKEN_REFRESH_URL = `${API_BASE}/api/token/refresh`;

let currentUser = null;

// ========== УПРАВЛЕНИЕ АВТОРИЗАЦИЕЙ (СЕРВЕР + JWT) ==========

// НОВОЕ: Обновление JWT-токена
async function refreshToken() {
  try {
    const { refreshToken } = await chrome.storage.local.get('refreshToken');
    if (!refreshToken) return null;
    
    const response = await fetch(API_TOKEN_REFRESH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: refreshToken })
    });
    
    if (response.ok) {
      const data = await response.json();
      await chrome.storage.local.set({ token: data.access });
      console.log('🔄 Токен обновлён');
      return data.access;
    } else {
      // Токен обновить не удалось — очищаем сессию
      await chrome.storage.local.remove(['token', 'refreshToken', 'user']);
      currentUser = null;
      return null;
    }
  } catch (e) {
    console.error('Ошибка обновления токена', e);
    return null;
  }
}

// НОВОЕ: Инициализация авторизации (проверка токена, загрузка пользователя)
async function initAuth() {
  try {
    const stored = await chrome.storage.local.get(['user', 'token']);
    
    if (stored.user && stored.token) {
      currentUser = stored.user;
      
      console.log('✅ Пользователь авторизован:', currentUser.email, 'План:', currentUser.plan);
      return true;
    } 
    else  {
      currentUser = null;
      console.log('❌ Пользователь не авторизован');
      return false;
    
    }

  } catch (error) {
    console.error('Ошибка инициализации авторизации:', error);
    return false;
  }
}

// Открытие окна регистрации/авторизации
async function openAuthWindow() {
  const windows = await chrome.windows.getAll();
  const authWindowExists = windows.some(w => w.type === 'popup');
  
  if (!authWindowExists) {
    chrome.windows.create({
      url: 'auth-panel.html',
      type: 'popup',
      width: 450,
      height: 620,
      focused: true
    });
  }
}

// НОВОЕ: Проверка лимита (сначала сервер, потом локальный fallback)
async function checkRateLimit() {
  const { token } = await chrome.storage.local.get('token');
  
  // Если нет токена — пользователь не авторизован, не даём проверять
  if (!token) {
    return { allowed: false, remaining: 0, limit: 0, error: 'Not authenticated' };
  }
  
  // Есть токен — запрос к серверу
  try {
    const response = await fetch(API_LIMIT_URL, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (response.ok) {
      const data = await response.json();
      const isPremium = data.is_premium === true;
      const remaining = isPremium ? Infinity : (data.remaining_checks || 0);
      const limit = isPremium ? Infinity : (data.limit || 10);
      
      return {
        allowed: isPremium || remaining > 0,
        remaining: remaining,
        limit: limit,
        isPremium: isPremium
      };
    }
  } catch (e) {
    console.warn('Не удалось получить лимит с сервера', e);
  }
  
  // Fallback (если сервер не ответил) — запрещаем проверку
  return { allowed: false, remaining: 0, limit: 0, error: 'Server unavailable' };
}
// ========== ОСНОВНЫЕ ФУНКЦИИ ПРОВЕРКИ ==========


// НОВОЕ: Функция запроса к API с авторизацией и обновлением токена
async function fetchWithAuth(url, options = {}) {
  const { token } = await chrome.storage.local.get('token');
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...options.headers
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  let response = await fetch(url, {
    ...options,
    headers: headers
  });
  
  // Если 401 и есть токен — пробуем обновить
  if (response.status === 401 && token) {
    const newToken = await refreshToken();
    if (newToken) {
      headers['Authorization'] = `Bearer ${newToken}`;
      response = await fetch(url, {
        ...options,
        headers: headers
      });
    }
  }
  
  return response;
}

// НОВОЕ: Отправка запроса к API /analyze с авторизацией
async function checkWithApi(url) {
  try {
    console.log('📤 Отправка запроса к API:', url);
    
    const response = await fetchWithAuth(API_ANALYZE_URL, {
      method: 'POST',
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        return { success: false, error: 'Сессия истекла, войдите снова', needsAuth: true };
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    console.log('📦 Ответ API:', data);
    return { success: true, data: data };
    
  } catch (error) {
    console.error('❌ Ошибка API запроса:', error);
    return { success: false, error: error.message };
  }
}

async function analyzeUrl(url) {
  console.log('🔍 Анализ URL:', url);
  if (url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') || 
      url.startsWith('edge://') || 
      url.startsWith('devtools://') ||
      url.startsWith('about://')) {
    console.log('⏭️ Служебная страница, пропускаем');
    return {
      riskLevel: 'safe',
      isPhishing: false,
      details: 'Служебная страница браузера'
    };
  }
  // Проверка авторизации
if (!currentUser) {
  return {
    riskLevel: 'error',
    details: '❌ Требуется регистрация! Войдите в аккаунт',
    needsAuth: true
  };
}
  
  // Проверка лимита
  const rateLimit = await checkRateLimit();
  if (!rateLimit.allowed) {
    const limitMsg = rateLimit.limit === Infinity ? 'безлимит' : rateLimit.limit;
    return {

      riskLevel: 'error',
      isPhishing: false,
      score: 0,
      details: `❌ Достигнут дневной лимит проверок. Оформите подписку Pro для безлимита!`,
      reason: 'Лимит проверок исчерпан. Оформите подписку →',
      source: 'limit',
      needsUpgrade: true,
      remainingChecks: rateLimit.remaining,
      timestamp: Date.now()
    };
  }
  
    
  // Запрос к API
  console.log('📡 Отправляем запрос к API...');
  const apiResult = await checkWithApi(url);
  
  if (apiResult.success && apiResult.data) {
    const data = apiResult.data;
    
    let isPhishing = false;
    let confidence = 0;
    let reason = '';
    let verdict = 'unknown';
    
    if (data.verdict) {
      verdict = data.verdict.toLowerCase();
      isPhishing = verdict === 'phishing';
      confidence = data.confidence || (isPhishing ? 100 : 0);
      reason = data.reason || (isPhishing ? 'Фишинговый сайт!' : 'Сайт безопасен');
    } else if (data.status) {
      verdict = data.status.toLowerCase();
      isPhishing = verdict === 'phishing';
      confidence = data.confidence || data.score || (isPhishing ? 100 : 0);
      reason = data.message || data.reason || (isPhishing ? 'Фишинговый сайт!' : 'Сайт безопасен');
    } else {
      console.warn('⚠️ Неизвестный формат ответа:', data);
      verdict = 'error';
      isPhishing = false;
      confidence = 0;
      reason = 'Неизвестный формат ответа сервера';
    }
    
    console.log(`📊 Результат: verdict=${verdict}, isPhishing=${isPhishing}, confidence=${confidence}`);
    
    return {
      riskLevel: isPhishing ? 'phishing' : (verdict === 'error' ? 'error' : 'safe'),
      isPhishing: isPhishing,
      score: confidence,
      details: reason,
      reason: reason,
      verdict: verdict,
      confidence: confidence,
      source: 'api',
      apiResponse: data,
      timestamp: Date.now(),
      remainingChecks: rateLimit.remaining
    };
  } else {
    console.error('❌ API недоступен:', apiResult.error);
    return {
      riskLevel: 'error',
      isPhishing: false,
      score: 0,
      details: `❌ Сервер проверки недоступен: ${apiResult.error || 'Неизвестная ошибка'}`,
      reason: `Ошибка подключения к серверу. Проверьте интернет.`,
      source: 'error',
      error: apiResult.error,
      timestamp: Date.now(),
      remainingChecks: rateLimit.remaining
    };
  }
}


// ========== ОБРАБОТЧИКИ СООБЩЕНИЙ ==========

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('📨 Получено сообщение:', request.type);
  
  if (request.type === 'CHECK_URL') {
    analyzeUrl(request.url)
  .then(result => {
    sendResponse({ success: true, result: result });  // ✅ прямо отправляем результат
  })
      .catch(error => {
        console.error('Ошибка при проверке:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }
if (request.type === 'PREMIUM_UPDATED') {
    // Обновляем данные пользователя с сервера
    (async () => {
        const { token } = await chrome.storage.local.get('token');
        if (token) {
            const response = await fetch('http://127.0.0.1:8000/api/user-info', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const userData = await response.json();
            await chrome.storage.local.set({
                user: {
                    id: userData.id,
                    name: userData.username,
                    email: userData.email,
                    plan: userData.is_premium ? 'pro' : 'free'
                }
            });
            // Уведомляем popup об изменении
            chrome.runtime.sendMessage({ type: 'USER_AUTH_CHANGED' });
        }
    })();
    sendResponse({ success: true });
    return true;
}
  if (request.type === 'GET_TOKEN') {
    chrome.storage.local.get('token', (data) => {
        sendResponse({ token: data.token });
    });
    return true;
}


  if (request.type === 'CHECK_AUTH') {
chrome.storage.local.get(['user', 'token'], (data) => {
  sendResponse({ 
    isLoggedIn: !!(data.user && data.token), 
    user: data.user || null,
    plan: data.user?.plan || 'free'
  });
});
    return true;
  }
  if (request.type === 'CLOSE_CURRENT_TAB') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            chrome.tabs.remove(tabs[0].id);
        }
    });
    sendResponse({ success: true });
    return true;
}
  if (request.type === 'GET_REMAINING_CHECKS') {
    checkRateLimit().then(rateLimit => {
      sendResponse({ 
        remaining: rateLimit.remaining === Infinity ? '∞' : rateLimit.remaining,
        used: rateLimit.limit === Infinity ? 0 : (rateLimit.limit - rateLimit.remaining),
        limit: rateLimit.limit === Infinity ? 'Безлимит' : rateLimit.limit
      });
    });
    return true;
  }
  // Обработчик QR-кодов
if (request.type === 'CHECK_QR_URL') {
    (async () => {
        try {
            const { token } = await chrome.storage.local.get('token');
            if (!token) {
                sendResponse({ success: false, error: 'Not authenticated' });
                return;
            }
            
            const response = await fetch('http://127.0.0.1:8000/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ url: request.url })
            });
            
            const result = await response.json();
            
            // Отправляем результат обратно в content script
            chrome.tabs.sendMessage(sender.tab.id, {
                type: 'QR_RESULT',
                url: request.url,
                isPhishing: result.verdict === 'phishing',
                reason: result.reason
            });
            
            sendResponse({ success: true });
        } catch (error) {
            console.error('QR: Ошибка проверки', error);
            sendResponse({ success: false, error: error.message });
        }
    })();
    return true;
}
  if (request.type === 'UPGRADE_TO_PRO') {
    chrome.tabs.create({ url: 'http://127.0.0.1:8000/premium' });
    sendResponse({ success: true });
  }
  
  if (request.type === 'USER_AUTH_CHANGED') {
    initAuth();
    sendResponse({ success: true });
    return true;
  }
  
  if (request.type === 'OPEN_AUTH_WINDOW') {
    openAuthWindow();
    sendResponse({ success: true });
    return true;
  }
});

// ========== ИНИЦИАЛИЗАЦИЯ ==========

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('🛡️ Secure Click Pro установлен');


  await initAuth();
});

chrome.runtime.onStartup.addListener(async () => {
  await initAuth();
});

initAuth();

// Слушаем навигацию для автоматической проверки
chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0 && details.url) {
    if (!details.url.startsWith('chrome://') && !details.url.startsWith('chrome-extension://')) {
      console.log('🌐 Автоматическая проверка при навигации:', details.url);
      analyzeUrl(details.url).then(result => {
        console.log('✅ Авто-проверка завершена:', result.verdict || result.riskLevel);
      });
    }
  }
});