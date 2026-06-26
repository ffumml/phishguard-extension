"""
URL configuration for phishguard_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
admin.site.site_header = "Security Click Admin"
admin.site.site_title = "Security Click"
admin.site.index_title = "Добро пожаловать в Security Click"
admin.site.favicon = "/static/favicon.ico"
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('payment-success', TemplateView.as_view(template_name='payment_success.html'), name='payment-success'),
]
