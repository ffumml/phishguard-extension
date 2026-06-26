from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import TokenRefreshView
from django.views.generic import TemplateView
urlpatterns = [
    path('analyze', views.analyze_url, name='analyze_url'),
    path('register', views.RegisterView.as_view(), name='register'),
    path('login', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('upgrade/confirm', views.upgrade_confirm, name='upgrade_confirm'),
    path('upgrade/initiate', views.upgrade_initiate, name='upgrade_initiate'),
    path('check-limit', views.check_limit, name='check_limit'),          # ← ДОБАВЬ ЭТУ СТРОКУ
    path('user-info', views.user_info, name='user_info'),
    path('deep-analyze', views.deep_analyze_url, name='deep_analyze'),
]
