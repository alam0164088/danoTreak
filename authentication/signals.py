# authentication/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, Profile

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    ইউজার তৈরি হলে Profile অটো তৈরি করো
    ইউজার আপডেট হলে Profile ও আপডেট করো (যদি থাকে)
    """
    if created:
        Profile.objects.create(user=instance)
        print(f"Profile created for new user: {instance.email}")
    else:
        # ইউজার আপডেট হলে Profile সেভ করো (যদি থাকে)
        if hasattr(instance, 'profile'):
            instance.profile.save()
            print(f"Profile saved for existing user: {instance.email}")

# অতিরিক্ত: যদি User-এ full_name থাকে, Profile-এ কপি করতে চান (অপশনাল)
@receiver(post_save, sender=User)
def sync_full_name_to_profile(sender, instance, created, **kwargs):
    if not created and hasattr(instance, 'profile') and instance.full_name:
        if instance.profile.full_name != instance.full_name:  # শুধু চেঞ্জ হলে
            instance.profile.full_name = instance.full_name
            instance.profile.save(update_fields=['full_name'])