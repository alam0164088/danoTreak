# dashboard/views.py
from rest_framework import viewsets, generics
from .models import Category, Phrase
from .serializers import CategorySerializer, PhraseSerializer, CategoryNameSerializer

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

class PhraseViewSet(viewsets.ModelViewSet):
    queryset = Phrase.objects.all()
    serializer_class = PhraseSerializer

    # নতুন যোগ করা অংশ
    def get_queryset(self):
        queryset = super().get_queryset()
        category_id = self.request.query_params.get('category')
        if category_id:
            queryset = queryset.filter(category_id=category_id)
        return queryset

class CategoryNameListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategoryNameSerializer