from django.urls import path
from .views import TranslateView, ParseTranslationRequestView, SupportedLanguagesView, ConversationHistoryView

app_name = 'bot'

urlpatterns = [
    path('translate/', TranslateView.as_view(), name='translate'),
    path('parse/', ParseTranslationRequestView.as_view(), name='parse_translation'),
    path('languages/', SupportedLanguagesView.as_view(), name='supported_languages'),
    path('history/', ConversationHistoryView.as_view(), name='conversation_history'),
]