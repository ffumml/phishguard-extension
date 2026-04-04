import os
import requests
from dotenv import load_dotenv
from rest_framework.decorators import api_view
from rest_framework.response import Response

# Загружаем переменные из .env
load_dotenv()

# Чёрный список
BLACKLIST = [
    "http://test-phishing.com",
    "https://fake-login.com",
]

# API-ключ из .env
YANDEX_API_KEY = os.getenv('YANDEX_API_KEY')

def check_yandex_safebrowsing(url):
    """Проверка URL через Yandex Safe Browsing API"""
    
    if not YANDEX_API_KEY:
        return {"verdict": "error", "message": "API ключ не найден"}
    
    yandex_url = "https://sba.yandex.net/v4/threatMatches:find"
    
    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    params = {"key": YANDEX_API_KEY}
    
    try:
        response = requests.post(yandex_url, params=params, json=payload, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # Если есть matches — сайт опасен
            if "matches" in data:
                return {"verdict": "phishing", "confidence": 95, "source": "yandex"}
            else:
                return {"verdict": "safe", "confidence": 90, "source": "yandex"}
        else:
            return {"verdict": "error", "message": f"Yandex API ошибка: {response.status_code}"}
            
    except Exception as e:
        return {"verdict": "error", "message": str(e)}

@api_view(['POST'])
def analyze_url(request):
    """Эндпоинт для проверки URL на фишинг"""
    
    url = request.data.get('url')
    
    # Уровень 1: чёрный список
    if url in BLACKLIST:
        return Response({
            'verdict': 'phishing',
            'confidence': 100,
            'reason': 'Сайт находится в чёрном списке'
        })
    
    # Уровень 2: Yandex Safe Browsing API
    yandex_result = check_yandex_safebrowsing(url)
    
    if yandex_result["verdict"] == "phishing":
        return Response({
            'verdict': 'phishing',
            'confidence': yandex_result["confidence"],
            'reason': 'Обнаружено Yandex Safe Browsing'
        })
    
    # Если всё чисто
    return Response({
        'verdict': 'safe',
        'confidence': 85,
        'reason': 'Сайт безопасен (проверен Яндексом)'
    })
