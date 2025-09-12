# payment/urls.py

from django.urls import path
from .views import PaymentCreateView, PaymentListView

urlpatterns = [
    path('payment/', PaymentCreateView.as_view(), name='payment_create'),
    path('payments/', PaymentListView.as_view(), name='payment_list'), # এই লাইনটি সঠিক ভাবে লেখা নিশ্চিত করুন
]