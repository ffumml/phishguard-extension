from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    is_premium = models.BooleanField(default=False)
    checks_today = models.IntegerField(default=0)
    last_check_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {'Premium' if self.is_premium else 'Free'}"
class Blacklist(models.Model):
    url = models.CharField(max_length=2048, unique=True)
    reason = models.CharField(max_length=255, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        print(f"✅ Профиль создан для {instance.username}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
