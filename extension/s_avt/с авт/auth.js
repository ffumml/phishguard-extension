// auth.js - Модуль авторизации для расширения
// Загружается в popup.html и background.js

class AuthManager {
  constructor() {
    this.user = null;
    this.subscription = null;
    this.listeners = [];
  }

  async init() {
    // Проверяем локальную сессию
    const stored = await chrome.storage.local.get(['user', 'token']);
    if (stored.user && stored.token) {
      this.user = stored.user;
      await this.verifyToken(stored.token);
    }
    return this.user;
  }

  async signUp(email, password, name = '') {
    try {
      const response = await fetch('https://your-backend.vercel.app/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name, plan: 'free' })
      });
      
      const data = await response.json();
      if (data.success) {
        this.user = data.user;
        await chrome.storage.local.set({ 
          user: this.user, 
          token: data.token 
        });
        this.notifyListeners();
        return { success: true, user: this.user };
      }
      return { success: false, error: data.error };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async signIn(email, password) {
    try {
      const response = await fetch('https://your-backend.vercel.app/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      if (data.success) {
        this.user = data.user;
        this.subscription = data.subscription;
        await chrome.storage.local.set({ 
          user: this.user, 
          token: data.token,
          subscription: this.subscription
        });
        this.notifyListeners();
        return { success: true, user: this.user };
      }
      return { success: false, error: data.error };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async signOut() {
    await chrome.storage.local.remove(['user', 'token', 'subscription']);
    this.user = null;
    this.subscription = null;
    this.notifyListeners();
  }

  async upgradeToPro() {
    // Создаём платёжную сессию (Stripe/YooKassa)
    const response = await fetch('https://your-backend.vercel.app/api/create-checkout', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await this.getToken()}`
      },
      body: JSON.stringify({ plan: 'pro', userId: this.user.id })
    });
    
    const data = await response.json();
    // Открываем окно оплаты
    chrome.tabs.create({ url: data.checkoutUrl });
    return data;
  }

  async checkLimit(endpoint = 'check') {
    if (!this.user) return { allowed: true, remaining: 100 }; // аноним 100/день
    
    const response = await fetch(`https://your-backend.vercel.app/api/check-limit`, {
      headers: { 'Authorization': `Bearer ${await this.getToken()}` }
    });
    const data = await response.json();
    return { allowed: data.allowed, remaining: data.remaining };
  }

  async getToken() {
    const stored = await chrome.storage.local.get(['token']);
    return stored.token;
  }

  async verifyToken(token) {
    // Валидация токена с сервером
    const response = await fetch('https://your-backend.vercel.app/api/verify', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) {
      await this.signOut();
      return false;
    }
    return true;
  }

  isPro() {
    return this.subscription?.plan === 'pro' || this.subscription?.plan === 'business';
  }

  onAuthChange(callback) {
    this.listeners.push(callback);
  }

  notifyListeners() {
    this.listeners.forEach(cb => cb(this.user, this.subscription));
  }
}

window.AuthManager = AuthManager;