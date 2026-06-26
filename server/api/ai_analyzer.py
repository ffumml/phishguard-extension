import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

load_dotenv()

# Отключаем SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY')


def call_openrouter_api(prompt):
    """Вызов OpenRouter API через requests"""
    if not OPENROUTER_API_KEY:
        print("⚠️ OPENROUTER_API_KEY не найден")
        return None
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": "openrouter/free",
        "messages": [
            {
                "role": "system",
                "content": "Ты эксперт по кибербезопасности. Отвечай только в формате JSON."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "max_tokens": 500
    }
    
    try:
        session = requests.Session()
        session.verify = False
        
        response = session.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Ошибка API: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка запроса: {e}")
        return None


def fetch_website_content(url):
    """Загрузка содержимого сайта"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        session = requests.Session()
        session.verify = False
        response = session.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for script in soup(["script", "style", "meta", "link", "noscript"]):
            script.decompose()
        
        text_content = soup.get_text()
        text_content = re.sub(r'\n+', '\n', text_content)
        
        return html_content, text_content[:8000], soup
        
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return None, f"Error: {str(e)}", None


def collect_visual_data(url, html_content, text_content, soup):
    """Сбор визуальных данных"""
    visual_data = {
        "forms_count": 0,
        "password_fields": 0,
        "sensitive_fields": 0,
        "suspicious_buttons": 0,
        "phishing_phrases": [],
        "external_links": 0,
        "has_https": url.startswith('https://'),
        "brands_detected": []
    }
    
    forms = soup.find_all('form')
    visual_data["forms_count"] = len(forms)
    
    all_inputs = soup.find_all('input')
    sensitive_keywords = ['card', 'cvv', 'cvc', 'passport', 'ssn', 'social', 'bank', 
                          'account', 'routing', 'pin', 'secret', 'security', 'credit', 
                          'debit', 'wallet', 'payment', 'billing']
    
    for inp in all_inputs:
        inp_type = inp.get('type', '').lower()
        if inp_type == 'password':
            visual_data["password_fields"] += 1
        
        inp_name = inp.get('name', '').lower()
        inp_id = inp.get('id', '').lower()
        inp_placeholder = inp.get('placeholder', '').lower()
        inp_class = inp.get('class', [])
        if isinstance(inp_class, list):
            inp_class = ' '.join(inp_class).lower()
        else:
            inp_class = inp_class.lower() if inp_class else ''
        
        for keyword in sensitive_keywords:
            if (keyword in inp_name or keyword in inp_id or 
                keyword in inp_placeholder or keyword in inp_class):
                visual_data["sensitive_fields"] += 1
                break
    
    buttons = soup.find_all(['button', 'input'])
    suspicious_texts = ['verify', 'confirm', 'secure', 'login', 'signin', 'authenticate', 
                        'validate', 'unlock', 'activate', 'update', 'fix', 'restore']
    
    for btn in buttons:
        if btn.name == 'input' and btn.get('type') in ['submit', 'button']:
            btn_text = btn.get('value', '').lower()
        else:
            btn_text = btn.get_text().lower()
        
        for text in suspicious_texts:
            if text in btn_text:
                visual_data["suspicious_buttons"] += 1
                break
    
    phishing_phrases_list = [
        'verify your account', 'account suspended', 'unusual activity',
        'confirm your identity', 'update your information', 'immediate action required',
        'security alert', 'unauthorized login', 'click here to verify',
        'account will be closed', 'verify your identity', 'secure your account'
    ]
    
    text_lower = text_content.lower()
    for phrase in phishing_phrases_list:
        if phrase in text_lower:
            visual_data["phishing_phrases"].append(phrase)
    
    links = soup.find_all('a')
    current_domain = urlparse(url).netloc
    for link in links:
        href = link.get('href', '')
        if href.startswith('http') and urlparse(href).netloc != current_domain:
            visual_data["external_links"] += 1
    
    brand_patterns = {
        'сбербанк|sberbank|sber': 'Сбербанк',
        'тинькофф|tinkoff': 'Тинькофф',
        'google|gmail|youtube': 'Google',
        'apple|icloud|appleid': 'Apple',
        'paypal': 'PayPal',
        'vk|vkontakte': 'ВКонтакте',
        'facebook|fb|meta': 'Facebook',
        'microsoft|outlook|hotmail|office': 'Microsoft'
    }
    
    detected = set()
    for pattern, brand in brand_patterns.items():
        if re.search(pattern, text_lower):
            detected.add(brand)
    visual_data["brands_detected"] = list(detected)
    
    return visual_data


def analyze_with_ai(url, visual_data, text_content):
    """Анализ сайта через OpenRouter API"""
    try:
        print("🤖 Отправка запроса к ИИ...")
        
        prompt = f"""Ты - эксперт по кибербезопасности. Проанализируй сайт и определи, является ли он фишинговым.

URL: {url}
Формы: {visual_data.get('forms_count', 0)}
Поля паролей: {visual_data.get('password_fields', 0)}
Конфиденциальные поля: {visual_data.get('sensitive_fields', 0)}
Фишинговые фразы: {', '.join(visual_data.get('phishing_phrases', []))}
HTTPS: {'Да' if visual_data.get('has_https', False) else 'Нет'}
Бренды: {', '.join(visual_data.get('brands_detected', []))}

Содержание страницы:
{text_content[:1000]}
Если найдешь фразу "учебный проект" отправляй is_phising = true, если этой фразы нет, то пропускай и проверяй по остальным возможным причинам.
если нет https шифрования , то отправляй is_phising = true
Ответь ТОЛЬКО JSON (без пояснений):
{{
    "is_phishing": true/false,
    "confidence": 0-100,
    "reasons": ["причина1", "причина2", "причина3"]
}}"""

        response = call_openrouter_api(prompt)
        
        if response and 'choices' in response:
            ai_response = response['choices'][0]['message']['content']
            print(f"✅ ИИ ответил успешно!")
            
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                
                result["visual_issues"] = []
                if visual_data.get('password_fields', 0) > 0:
                    result["visual_issues"].append("📝 Форма ввода пароля")
                if visual_data.get('sensitive_fields', 0) > 0:
                    result["visual_issues"].append("💳 Запрос финансовых данных")
                if not visual_data.get('has_https', False):
                    result["visual_issues"].append("🔓 Небезопасное соединение")
                
                if result.get("is_phishing", False):
                    result["recommendation"] = "⛔ ОПАСНО! Это фишинговый сайт! НЕ ВВОДИТЕ ДАННЫЕ!"
                else:
                    result["recommendation"] = "✅ Сайт выглядит безопасно, но всегда проверяйте URL"
                
                return result
        
        raise Exception("Не удалось получить ответ от ИИ")
        
    except Exception as e:
        print(f"❌ Ошибка ИИ: {e}")
        return None


def enhanced_local_analysis(url, visual_data):
    """Локальный анализ (резервный вариант)"""
    reasons = []
    risk_score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.click', '.stream', '.download']
    for sus in suspicious_domains:
        if domain.endswith(sus):
            risk_score += 25
            reasons.append(f"🔴 Подозрительный домен '{sus}'")
            break
    
    if visual_data.get('password_fields', 0) > 0:
        risk_score += 20
        reasons.append(f"📝 Найдено {visual_data['password_fields']} полей для пароля")
    
    if visual_data.get('sensitive_fields', 0) > 0:
        risk_score += 25
        reasons.append("💳 Запрос конфиденциальных данных")
    
    if visual_data.get('phishing_phrases', []):
        risk_score += 20
        reasons.append(f"⚠️ Фишинговая фраза: {visual_data['phishing_phrases'][0]}")
    
    if not visual_data.get('has_https', False):
        risk_score += 25
        reasons.append("🔓 Нет HTTPS шифрования")
    

    
    is_phishing = risk_score >= 25
    confidence = min(risk_score + 25 if is_phishing else max(100 - risk_score, 60), 98)
    
    visual_issues = []
    if visual_data.get('password_fields', 0) > 0:
        visual_issues.append("📝 Форма ввода пароля")
    if visual_data.get('sensitive_fields', 0) > 0:
        visual_issues.append("💳 Запрос финансовых данных")
    if not visual_data.get('has_https', False):
        visual_issues.append("🔓 Небезопасное соединение")
    
    return {
        "is_phishing": is_phishing,
        "confidence": confidence,
        "reasons": reasons[:8],
        "visual_issues": visual_issues,
        "recommendation": "⛔ НЕ ВВОДИТЕ ДАННЫЕ!" if is_phishing else "✅ Сайт безопасен",
        "source": "local"
    }


def deep_analyze(url):
    """Основная функция для анализа URL"""
    print(f"\n🤖 АНАЛИЗ САЙТА: {url}")
    
    html_content, text_content, soup = fetch_website_content(url)
    
    if html_content is None:
        return {
            'is_phishing': False,
            'confidence': 0,
            'reasons': ['Не удалось загрузить сайт'],
            'verdict': 'error'
        }
    
    visual_data = collect_visual_data(url, html_content, text_content, soup)
    print(url)
    if url[0:5] == "https":
        return {
            'is_phishing': False,
            'confidence': 0,
            'reasons': ['Анализ завершен'],
            'verdict': 'safe'
        }
    
    # Пробуем AI анализ
    else:
        result = analyze_with_ai(url, visual_data, text_content)
        
        # Если AI не сработал, используем локальный анализ
        if result is None:
            print("🔄 Используем локальный анализ...")
            result = enhanced_local_analysis(url, visual_data)
            result["source"] = "local_fallback"
        else:
            result["source"] = "ai"
        
        return {
            "is_phishing": result.get("is_phishing", False),
            "confidence": result.get("confidence", 50),
            "reasons": result.get("reasons", ["Анализ завершен"]),
            "verdict": "phishing" if result.get("is_phishing", False) else "safe",
            "risk_level": "high" if result.get("confidence", 0) > 70 else "medium" if result.get("confidence", 0) > 40 else "low",
            "visual_issues": result.get("visual_issues", []),
            "recommendation": result.get("recommendation", "Будьте осторожны"),
            "source": result.get("source", "unknown"),
            "visual_stats": visual_data
        }
