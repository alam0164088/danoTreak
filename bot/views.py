
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .utils import AITranslatorChatbot
from .serializers import (
    TranslationRequestSerializer,
    TranslationResponseSerializer,
    LanguageSerializer,
    SpecialCommandResponseSerializer
)
from rest_framework.permissions import IsAuthenticated

class TranslateView(APIView):
    permission_classes = []  # No authentication for testing

    def post(self, request):
        print("Request data:", request.data)  # Debug line
        serializer = TranslationRequestSerializer(data=request.data)
        if serializer.is_valid():
            chatbot = AITranslatorChatbot()
            result = chatbot.translate_text(
                text=serializer.validated_data['text'],
                target_language=serializer.validated_data['target_language'],
                source_language=serializer.validated_data.get('source_language')
            )
            response_serializer = TranslationResponseSerializer(data=result)
            if response_serializer.is_valid():
                return Response(response_serializer.data, status=status.HTTP_200_OK)
            return Response(response_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ParseTranslationRequestView(APIView):
    permission_classes = []  # Changed to disable authentication

    def post(self, request):
        input_text = request.data.get('input', '')
        if not input_text:
            return Response({'error': 'Input text is required'}, status=status.HTTP_400_BAD_REQUEST)
        chatbot = AITranslatorChatbot()
        special_response = chatbot.handle_special_commands(input_text)
        if special_response:
            response_serializer = SpecialCommandResponseSerializer(data=special_response)
            if response_serializer.is_valid():
                return Response(response_serializer.data, status=status.HTTP_200_OK)
            return Response(response_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        parsed = chatbot.parse_translation_request(input_text)
        if parsed['is_translation_request']:
            result = chatbot.translate_text(
                text=parsed['text'],
                target_language=parsed['target_language']
            )
            response_serializer = TranslationResponseSerializer(data=result)
            if response_serializer.is_valid():
                history_entry = {
                    'timestamp': timezone.now().isoformat(),
                    'user': input_text,
                    'bot': f"{parsed['conversational_response']}\nTranslation completed: {result['source_language']} → {result['target_language']}",
                    'parsed_request': parsed
                }
                chatbot.conversation_history.append(history_entry)
                return Response({
                    'conversational_response': parsed['conversational_response'],
                    'translation': response_serializer.data
                }, status=status.HTTP_200_OK)
            return Response(response_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'conversational_response': parsed['conversational_response'],
            'translation': None
        }, status=status.HTTP_200_OK)

class SupportedLanguagesView(APIView):
    permission_classes = []  # Public endpoint

    def get(self, request):
        chatbot = AITranslatorChatbot()
        languages = chatbot.get_supported_languages()
        serializer = LanguageSerializer(languages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ConversationHistoryView(APIView):
    permission_classes = []  # Changed to disable authentication

    def get(self, request):
        chatbot = AITranslatorChatbot()
        history = chatbot.get_conversation_history()
        return Response(history, status=status.HTTP_200_OK)
