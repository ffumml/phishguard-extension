from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile  # ← ДОБАВЬ ЭТУ СТРОКУ

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # В поле username приходит email (так как в расширении мы отправляем email)
        email = attrs.get('username')
        password = attrs.get('password')
        
        try:
            user = User.objects.get(email=email)  # ← поиск по email
        except User.DoesNotExist:
            raise serializers.ValidationError('No active account found with the given credentials')
        
        if not user.check_password(password):
            raise serializers.ValidationError('No active account found with the given credentials')
        
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled')
        
        try:
            profile = user.profile
            plan = 'pro' if profile.is_premium else 'free'
        except UserProfile.DoesNotExist:
            plan = 'free'
        
        refresh = self.get_token(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'plan': plan
            }
        }
        return data

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password']
        )
       
        return user
