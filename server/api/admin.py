from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import Blacklist

# Отменяем регистрацию стандартной модели User (если она зарегистрирована)
try:
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass

# Регистрируем свою версию User
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'is_staff', 'is_active', 'date_joined')
    search_fields = ('username', 'email')
    list_filter = ('is_staff', 'is_active')

# Регистрируем чёрный список
@admin.register(Blacklist)
class BlacklistAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'reason', 'added_at')
    search_fields = ('url',)
    list_filter = ('added_at',)
