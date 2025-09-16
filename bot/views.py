from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import ChatRequestSerializer, ChatResponseSerializer, AllLanguagesResponseSerializer
from .translator import AITranslatorChatbot

class ChatView(APIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.chatbot = AITranslatorChatbot()

    def post(self, request):
        serializer = ChatRequestSerializer(data=request.data)
        if serializer.is_valid():
            user_input = serializer.validated_data['input']
            parsed_request = self.chatbot.parse_translation_request(user_input)
            
            response_data = parsed_request.copy()
            if parsed_request['is_translation_request']:
                if parsed_request['target_language'] == 'all':
                    translations = self.chatbot.translate_to_all_languages(parsed_request['text'])
                    response_data = {'translations': translations}
                    response_serializer = AllLanguagesResponseSerializer(response_data)
                else:
                    translation_result = self.chatbot.translate_text(
                        parsed_request['text'],
                        parsed_request['target_language']
                    )
                    response_data['translation_result'] = translation_result
                    response_serializer = ChatResponseSerializer(response_data)
            else:
                response_serializer = ChatResponseSerializer(response_data)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LanguagesView(APIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.chatbot = AITranslatorChatbot()

    def get(self, request):
        return Response(self.chatbot.supported_languages, status=status.HTTP_200_OK)