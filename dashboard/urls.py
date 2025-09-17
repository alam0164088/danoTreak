# dashboard/urls.py
from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import CategoryViewSet, PhraseViewSet, CategoryNameListView

router = DefaultRouter()
router.register(r'categories', CategoryViewSet)
router.register(r'phrases', PhraseViewSet)

urlpatterns = router.urls + [
    path('category-names/', CategoryNameListView.as_view(), name='category-names'),
]