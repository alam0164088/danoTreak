# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, Profile

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
        if instance.full_name:
            instance.profile.full_name = instance.full_name
            instance.profile.save()
    else:
        if hasattr(instance, 'profile'):
            instance.profile.save()