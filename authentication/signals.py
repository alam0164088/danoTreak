from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, Profile

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
            employee_id=str(instance.id),  # Set employee_id to User.id
            full_name=instance.username   # Set full_name to username
        )
    else:
        if hasattr(instance, 'profile'):
            instance.profile.full_name = instance.profile.full_name or instance.username
            instance.profile.save()