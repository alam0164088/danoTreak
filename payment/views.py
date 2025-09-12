# payment/views.py

from rest_framework import generics, status
from rest_framework.response import Response
from .models import Payment
from .serializers import PaymentSerializer
from authentication.models import User
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated


class PaymentCreateView(generics.CreateAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    permission_classes = [IsAuthenticated] 

    def create(self, request, *args, **kwargs):
        # The serializer expects a primary key (pk) value, not a full object.
        # So, we pass the original request.data directly to the serializer.
        serializer = self.get_serializer(data=request.data)
        
        try:
            # The serializer handles validation and object creation.
            # is_valid() will check if the user ID exists and is a valid integer.
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "Payment processed successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        except Exception as e:
            # We are catching all exceptions here for simplicity
            # but a better practice is to catch specific ones.
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PaymentListView(generics.ListAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer

    def get_queryset(self):
        user_id = self.request.query_params.get('user_id', None)
        if user_id:
            try:
                user_id = int(user_id)  # Validate user_id is integer
                return Payment.objects.filter(user_id=user_id)
            except (ValueError, TypeError):
                return Payment.objects.none()
        return Payment.objects.all()