from rest_framework.routers import DefaultRouter
from .views import CategoryViewSet, PhraseViewSet, CategoryNameViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet)
router.register(r'phrases', PhraseViewSet)
router.register(r'category-names', CategoryNameViewSet, basename='category-names')

urlpatterns = router.urls
