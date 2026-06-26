// QR-сканер для PRO пользователей
let scannerActive = false;
let processedQRCodes = new Set(); // запоминаем уже обработанные QR на этой странице

// Проверяем, PRO ли пользователь
async function checkIsPro() {
    const { user } = await chrome.storage.local.get('user');
    const isPro = user && user.plan === 'pro';
    console.log('QR: PRO статус (из storage):', isPro);
    
    if (isPro && !scannerActive) {
        startScanning();
    }
}

// Запуск сканирования
function startScanning() {
    scannerActive = true;
    console.log('QR: Сканер запущен для PRO');
    
    // Сбрасываем Set при загрузке новой страницы
    processedQRCodes.clear();
    
    setTimeout(() => {
        findQRCodes();
        const observer = new MutationObserver(() => findQRCodes());
        observer.observe(document.body, { childList: true, subtree: true });
    }, 1000);
}

// Поиск QR-кодов
function findQRCodes() {
    const images = document.querySelectorAll('img');
    const canvases = document.querySelectorAll('canvas');
    
    images.forEach(img => {
        if (img.complete && img.naturalHeight > 0) {
            decodeQR(img);
        } else {
            img.addEventListener('load', () => decodeQR(img));
        }
    });
    
    canvases.forEach(canvas => decodeQR(canvas));
}

// Декодирование QR
function decodeQR(element) {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = element.naturalWidth || element.width || 200;
        canvas.height = element.naturalHeight || element.height || 200;
        
        if (canvas.width === 0 || canvas.height === 0) return;
        
        ctx.drawImage(element, 0, 0, canvas.width, canvas.height);
        
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, canvas.width, canvas.height);
        
        if (code && code.data) {
            const url = code.data;
            if (url.startsWith('http')) {
                // Проверяем, не обрабатывали ли этот QR уже на этой странице
                if (processedQRCodes.has(url)) {
                    return;
                }
                
                console.log('QR: Найден QR с URL:', url.substring(0, 50));
                processedQRCodes.add(url);
                
                chrome.runtime.sendMessage({ 
                    type: 'CHECK_QR_URL', 
                    url: url 
                });
            }
        }
    } catch (e) {}
}

// Показать предупреждение
function showQRWarning(url, reason) {
    // Удаляем старое предупреждение, если есть
    const oldWarning = document.querySelector('[id^="qr-warning-"]');
    if (oldWarning) oldWarning.remove();
    
    const warning = document.createElement('div');
    warning.id = `qr-warning-${Date.now()}`;
    warning.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 10001;
        background: #ef4444;
        color: white;
        padding: 12px 16px;
        border-radius: 12px;
        font-size: 14px;
        max-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        font-family: sans-serif;
        animation: slideInRight 0.3s ease;
    `;
    warning.innerHTML = `
        <strong>⚠️ Опасный QR-код!</strong><br>
        ${reason || 'Ссылка ведёт на фишинговый сайт'}<br>
     
    `;
    document.body.appendChild(warning);
    setTimeout(() => warning.remove(), 10000);
}

// Слушаем ответ от background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'QR_RESULT') {
        if (request.isPhishing) {
            showQRWarning(request.url, request.reason);
        }
        sendResponse({ success: true });
    }
    return true;
});

// Запускаем
checkIsPro();