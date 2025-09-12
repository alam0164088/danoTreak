from rest_framework import serializers
from .models import Payment
from authentication.serializers import SubscriptionPlanSerializer

class PaymentSerializer(serializers.ModelSerializer):
    subscription_plan = SubscriptionPlanSerializer(read_only=True)

    class Meta:
        model = Payment
        fields = ['id', 'user', 'email', 'payment_method', 'amount', 'subscription_plan', 'created_at']