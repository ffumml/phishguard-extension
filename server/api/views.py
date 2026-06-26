import os
import requests
from dotenv import load_dotenv
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from django.utils import timezone
import uuid
from .serializers import RegisterSerializer, CustomTokenObtainPairSerializer
from .models import UserProfile
from django.urls import reverse
from .ai_analyzer import deep_analyze
load_dotenv()

# ========== JWT С КАСТОМНЫМИ ДАННЫМИ ==========
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# ========== РЕГИСТРАЦИЯ ==========
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'is_premium': False,
                'checks_today': 0,
                'last_check_date': None
            }
        )
        return Response({
            "user": {
                "username": user.username,
                "email": user.email,
            },
            "message": "Пользователь успешно зарегистрирован"
        }, status=status.HTTP_201_CREATED)

# ========== ЧЁРНЫЙ СПИСОК ==========
BLACKLIST = [
    "http://test-phishing.com",
    "https://fake-login.com",
    "http://nangelqn.beget.tech/phone-login.html",
    "http://nangelqn.beget.tech/QR.html",
]

# ========== YANDEX API ==========
YANDEX_API_KEY = os.getenv('YANDEX_API_KEY')

def check_yandex_safebrowsing(url):
    if not YANDEX_API_KEY:
        return {"verdict": "error", "message": "API ключ не найден"}
    
    yandex_url = "https://sba.yandex.net/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
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
            if "matches" in data:
                return {"verdict": "phishing", "confidence": 95, "source": "yandex"}
            else:
                return {"verdict": "safe", "confidence": 90, "source": "yandex"}
        else:
            return {"verdict": "error", "message": f"Yandex API ошибка: {response.status_code}"}
    except Exception as e:
        return {"verdict": "error", "message": str(e)}

# ========== ОСНОВНАЯ ПРОВЕРКА ==========
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def analyze_url(request):
    url = request.data.get('url')
    profile = request.user.profile

    today = timezone.now().date()
    if profile.last_check_date != today:
        profile.checks_today = 0
        profile.last_check_date = today
        profile.save()

    if not profile.is_premium and profile.checks_today >= 10:
        return Response({
            'error': 'Дневной лимит проверок (10) исчерпан. Оформите премиум.',
            'remaining': 0,
            'code': 'limit_exceeded'
        }, status=403)

    if url in BLACKLIST:
        return Response({
            'verdict': 'phishing',
            'confidence': 100,
            'reason': 'Сайт в чёрном списке'
        })

    
    yandex_result = check_yandex_safebrowsing(url)
    profile.checks_today += 1
    profile.save()

    if yandex_result["verdict"] == "phishing":
        return Response({
            'verdict': 'phishing',
            'confidence': yandex_result["confidence"],
            'reason': 'Сайт признан фишинговым'
        })
    
    return Response({
        'verdict': 'safe',
        'confidence': 85,
        'reason': 'Сайт безопасен'
    })

# ========== ПРОВЕРКА ЛИМИТОВ ==========
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_limit(request):
    profile = request.user.profile
    today = timezone.now().date()
    
    # Сброс счётчика в новый день
    if profile.last_check_date != today:
        profile.checks_today = 0
        profile.last_check_date = today
        profile.save()
    
    # Для премиум — безлимит
    if profile.is_premium:
        return Response({
            'is_premium': True,
            'remaining_checks': '∞',
            'limit': 'Безлимит'
        })
    
    # Для обычных пользователей
    remaining = max(0, 10 - profile.checks_today)
    return Response({
        'is_premium': False,
        'remaining_checks': remaining,
        'limit': 10
    })

temp_payment_sessions = {}

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upgrade_initiate(request):
    session_id = str(uuid.uuid4())
    temp_payment_sessions[session_id] = {
        'user_id': request.user.id,
        'created_at': timezone.now(),
        'status': 'pending'
    }
    payment_url = request.build_absolute_uri(reverse('payment-success'))
    
    return Response({
        'session_id': session_id,
        'redirect_url': f'{payment_url}?session={session_id}'
    })
@api_view(['GET'])
def upgrade_confirm(request):
    session_id = request.GET.get('session')
    session = temp_payment_sessions.get(session_id)
    
    if not session:
        return Response({'error': 'Сессия не найдена'}, status=404)
    
    if session['status'] != 'pending':
        return Response({'message': 'Сессия уже обработана'}, status=400)
    
    # Обновляем статус сессии
    session['status'] = 'completed'
    
    # Обновляем пользователя до премиум
    from django.contrib.auth.models import User
    user = User.objects.get(id=session['user_id'])
    profile = user.profile
    profile.is_premium = True
    profile.save()
    
    return Response({
        'message': 'Аккаунт обновлён до Premium!',
        'is_premium': True
    })
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_info(request):
    profile = request.user.profile
    return Response({
        'id': request.user.id,
        'username': request.user.username,
        'email': request.user.email,
        'is_premium': profile.is_premium,
        'plan': 'pro' if profile.is_premium else 'free'
    })
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deep_analyze_url(request):
    url = request.data.get('url')
    
    if not url:
        return Response({'error': 'URL не указан'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        result = deep_analyze(url)
        
        # Упрощаем ответ — только то, что нужно расширению
        simplified = {
            'verdict': result.get('verdict', 'error'),
            'is_phishing': result.get('is_phishing', False),
            'reason': result.get('reasons', ['Анализ завершен'])[0] if result.get('reasons') else 'Анализ завершен'
        }
        return Response(simplified)
        
    except Exception as e:
        return Response({
            'verdict': 'error',
            'is_phishing': False,
            'reason': f'Ошибка анализа: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
