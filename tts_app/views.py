# tts_app/views.py
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from gtts import gTTS, lang as gtts_langs
import requests
import os
import uuid
from django.conf import settings
from django.http import HttpResponse
from pydub import AudioSegment  # pip install pydub
import io

@method_decorator(csrf_exempt, name='dispatch')
class TranslateAndTTSAPIView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        text = request.data.get("text")
        lang_code = request.data.get("lang") or request.data.get("target_lang")

        if not text:
            return Response({"error": "No text provided."}, status=400)
        if not lang_code:
            return Response({"error": "No language selected."}, status=400)

        # Google Translate API
        API_URL = "https://translation.googleapis.com/language/translate/v2"
        API_KEY = settings.GOOGLE_API_KEY

        try:
            payload = {"q": text, "target": lang_code}
            headers = {"Content-Type": "application/json"}
            response = requests.post(f"{API_URL}?key={API_KEY}", json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            translated_text = result["data"]["translations"][0]["translatedText"]
        except Exception as e:
            return Response({"error": f"Translation failed: {str(e)}"}, status=500)

        supported_langs = gtts_langs.tts_langs()
        audio_url = "not found audio"

        if lang_code in supported_langs:
            try:
                os.makedirs(settings.MEDIA_ROOT, exist_ok=True)
                file_name = f"{uuid.uuid4()}_{lang_code}.mp3"
                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                # Step 1: gTTS generate
                tts = gTTS(text=translated_text, lang=lang_code, slow=False)
                temp_fp = io.BytesIO()
                tts.write_to_fp(temp_fp)
                temp_fp.seek(0)

                # Step 2: Load audio with pydub
                audio = AudioSegment.from_file(temp_fp, format="mp3")

                # Step 3: Lower pitch for male-like voice (same for all languages)
                audio = audio._spawn(audio.raw_data, overrides={
                    "frame_rate": int(audio.frame_rate * 0.85)  # lower pitch -> male
                }).set_frame_rate(audio.frame_rate)

                # Step 4: Export final
                audio.export(file_path, format="mp3")

                audio_url = request.build_absolute_uri(settings.MEDIA_URL + file_name)
            except Exception as e:
                audio_url = f"not found audio ({str(e)})"

        return Response({
            "original_text": text,
            "translated_text": translated_text,
            "audio_url": audio_url
        })


def home(request):
    return HttpResponse("Welcome to Help Me Speak")
