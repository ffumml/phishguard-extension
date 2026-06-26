// premium.js
const API_BASE = 'http://127.0.0.1:8000';

document.addEventListener('DOMContentLoaded', () => {
    const upgradeBtn = document.getElementById('upgradeBtn');
    
    upgradeBtn.addEventListener('click', async () => {
        try {
            const { token } = await chrome.storage.local.get('token');

            if (!token) {
                alert('Вы не авторизованы. Войдите в расширение.');
                return;
            }

            const response = await fetch(`${API_BASE}/api/upgrade/initiate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            });

            const data = await response.json();
            if (response.ok && data.redirect_url) {
                window.location.href = data.redirect_url;
            } else {
                alert('Ошибка: ' + (data.error || 'Неизвестная ошибка'));
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Ошибка подключения к серверу');
        }
    });
});