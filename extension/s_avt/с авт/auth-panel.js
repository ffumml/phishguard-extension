// auth-panel.js — без гостевого режима
const API_BASE = 'http://127.0.0.1:8000'; 

function showError(elementId, message) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = message;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
  }
}

async function saveUserToExtension(user, accessToken, refreshToken) {
  await chrome.storage.local.set({
    user: {
      id: user.id,
      name: user.username,
      email: user.email,
      plan: user.plan || 'free'
    },
    token: accessToken,
    refreshToken: refreshToken,
    isGuest: false
  });
  chrome.runtime.sendMessage({ type: 'USER_AUTH_CHANGED' });
}

window.doLogin = async function() {
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!email || !password) {
    showError('loginError', 'Заполните все поля');
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: email, password: password })
    });
    const data = await response.json();
console.log('🔵 Ответ сервера:', data);
    if (response.ok && data.access) {
console.log('🔵 Вызываем saveUserToExtension с user:', data.user);
      await saveUserToExtension(data.user, data.access, data.refresh);
      renderUserPanel(data.user);
    } else {
      showError('loginError', data.detail || 'Неверный email или пароль');
    }
  } catch (error) {
    showError('loginError', 'Ошибка соединения с сервером');
  }
};

window.doRegister = async function() {
  const name = document.getElementById('regName').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const confirm = document.getElementById('regConfirm').value;

  if (!name || !email || !password) {
    showError('registerError', 'Заполните все поля');
    return;
  }
  if (password !== confirm) {
    showError('registerError', 'Пароли не совпадают');
    return;
  }
  if (password.length < 6) {
    showError('registerError', 'Пароль должен быть не менее 6 символов');
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: name,
        email: email,
        password: password,
        plan: 'free'
      })
    });

    if (response.ok) {
      const loginRes = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, password: password })
      });
      const loginData = await loginRes.json();

      if (loginRes.ok && loginData.access) {
        await saveUserToExtension(loginData.user, loginData.access, loginData.refresh);
        renderUserPanel(loginData.user);
      } else {
        showError('registerError', 'Регистрация успешна, но не удалось войти');
        switchTab('login');
      }
    } else {
      const err = await response.json();
      showError('registerError', err.detail || err.email?.[0] || 'Ошибка регистрации');
    }
  } catch (error) {
    showError('registerError', 'Ошибка соединения с сервером');
  }
};

function renderUserPanel(user) {
  const container = document.getElementById('authContainer');
  const userContainer = document.getElementById('userContainer');
  container.style.display = 'none';
  userContainer.style.display = 'block';
  const isPro = user.plan === 'pro';
  
  userContainer.innerHTML = `
    <div style="text-align: center;">
      <div class="user-avatar">${user.name ? user.name[0].toUpperCase() : 'U'}</div>
      <div style="font-size: 18px; font-weight: bold;">${user.name || user.email}</div>
      <div style="font-size: 12px; color: #94a3b8; margin-bottom: 20px;">${user.email}</div>
      <div style="background: rgba(16,185,129,0.1); border-radius: 12px; padding: 12px; margin-bottom: 20px;">
        <div style="color: #6ee7b7;">✅ Вы успешно авторизованы!</div>
      </div>
      <div style="margin-bottom: 20px;">📊 План: ${isPro ? '⭐ PRO' : '📊 Free (10/день)'}</div>
      <button id="closeWindowBtn" style="background:rgba(255,255,255,0.2);">Закрыть</button>
      <button id="logoutBtn" style="background:rgba(239,68,68,0.3); margin-top:10px;">Выйти</button>
    </div>
  `;
  
  // Обработчики событий
  document.getElementById('closeWindowBtn')?.addEventListener('click', () => {
    window.close();
  });
  
  document.getElementById('logoutBtn')?.addEventListener('click', async () => {
    await chrome.storage.local.remove(['user', 'token', 'refreshToken', 'isGuest']);
    chrome.runtime.sendMessage({ type: 'USER_AUTH_CHANGED' });
    renderAuthPanel();
  });
}
function renderAuthPanel() {
  const container = document.getElementById('authContainer');
  const userContainer = document.getElementById('userContainer');
  container.style.display = 'block';
  userContainer.style.display = 'none';

  container.innerHTML = `
    <div class="tabs">
      <div class="tab active" data-tab="login">Вход</div>
      <div class="tab" data-tab="register">Регистрация</div>
    </div>
    <div id="loginForm" class="form active">
      <div id="loginError" class="error"></div>
      <input type="email" id="loginEmail" placeholder="Email">
      <input type="password" id="loginPassword" placeholder="Пароль">
      <button id="loginBtn">Войти →</button>
    </div>
    <div id="registerForm" class="form">
      <div id="registerError" class="error"></div>
      <input type="text" id="regName" placeholder="Имя">
      <input type="email" id="regEmail" placeholder="Email">
      <input type="password" id="regPassword" placeholder="Пароль (мин. 6 символов)">
      <input type="password" id="regConfirm" placeholder="Подтвердите пароль">
      <button id="registerBtn">Создать аккаунт</button>
    </div>
  `;

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.getAttribute('data-tab');
      switchTab(tabName);
    });
  });

  document.getElementById('loginBtn')?.addEventListener('click', doLogin);
  document.getElementById('registerBtn')?.addEventListener('click', doRegister);

  }



window.switchTab = function(tab) {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const tabs = document.querySelectorAll('.tab');
  if (tab === 'login') {
    loginForm.classList.add('active');
    registerForm.classList.remove('active');
    tabs[0].classList.add('active');
    tabs[1].classList.remove('active');
  } else {
    loginForm.classList.remove('active');
    registerForm.classList.add('active');
    tabs[0].classList.remove('active');
    tabs[1].classList.add('active');
  }
};

window.doLogout = async function() {
  console.log('Выход из аккаунта');
  
  // Удаляем данные пользователя
  await chrome.storage.local.remove(['user', 'token', 'refreshToken', 'isGuest']);
  
  // Уведомляем все части расширения о выходе
  chrome.runtime.sendMessage({ type: 'USER_AUTH_CHANGED' });
  
  // Закрываем окно авторизации
  window.close();
};

(async () => {
  const { user, isGuest } = await chrome.storage.local.get(['user', 'isGuest']);
  if (user && !isGuest) {
    renderUserPanel(user);
  } else {
    renderAuthPanel();
  }
})();