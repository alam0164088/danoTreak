
import os
import json
import re
import requests
from typing import Optional, Dict, List
from django.conf import settings
from datetime import datetime

class AITranslatorChatbot:
    def __init__(self):
        self.google_api_key = settings.GOOGLE_API_KEY
        if not self.google_api_key:
            raise ValueError("GOOGLE_API_KEY not set in settings")
        
        self.supported_languages = {}
        self.conversation_history = []
        self.load_supported_languages()

    def load_supported_languages(self):
        """Load supported languages from Google Translate API"""
        try:
            url = f"https://translation.googleapis.com/language/translate/v2/languages?key={self.google_api_key}&target=en"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                languages = data['data']['languages']
                self.supported_languages = {lang['language']: lang.get('name', lang['language']) for lang in languages}
            else:
                raise Exception(f"API request failed: {response.status_code}")
        except Exception as e:
            self.supported_languages = {
                'en': 'English', 'es': 'Spanish', 'fr': 'French', 'de': 'German',
                'it': 'Italian', 'pt': 'Portuguese', 'ru': 'Russian', 'zh': 'Chinese',
                'ja': 'Japanese', 'ko': 'Korean', 'ar': 'Arabic', 'hi': 'Hindi'
            }

    def find_language_code(self, language_name: str) -> Optional[str]:
        """Find language code from language name"""
        if not language_name:
            return None
        language_name = language_name.lower().strip()
        if language_name in self.supported_languages:
            return language_name
        language_name_to_code = {
            'spanish': 'es', 'french': 'fr', 'german': 'de', 'italian': 'it',
            'portuguese': 'pt', 'russian': 'ru', 'chinese': 'zh', 'japanese': 'ja',
            'korean': 'ko', 'arabic': 'ar', 'hindi': 'hi', 'dutch': 'nl',
            'swedish': 'sv', 'norwegian': 'no', 'danish': 'da', 'finnish': 'fi',
            'polish': 'pl', 'turkish': 'tr', 'greek': 'el', 'hebrew': 'iw',
            'thai': 'th', 'vietnamese': 'vi', 'indonesian': 'id', 'malay': 'ms',
            'bengali': 'bn', 'urdu': 'ur', 'tamil': 'ta', 'telugu': 'te',
            'gujarati': 'gu', 'kannada': 'kn', 'malayalam': 'ml', 'marathi': 'mr',
            'punjabi': 'pa', 'czech': 'cs', 'hungarian': 'hu', 'romanian': 'ro',
            'bulgarian': 'bg', 'croatian': 'hr', 'serbian': 'sr', 'slovak': 'sk',
            'slovenian': 'sl', 'lithuanian': 'lt', 'latvian': 'lv', 'estonian': 'et',
            'ukrainian': 'uk', 'belarusian': 'be', 'catalan': 'ca', 'basque': 'eu',
            'galician': 'gl', 'welsh': 'cy', 'irish': 'ga', 'scots': 'gd',
            'albanian': 'sq', 'macedonian': 'mk', 'bosnian': 'bs', 'afrikaans': 'af',
            'swahili': 'sw', 'zulu': 'zu', 'xhosa': 'xh', 'yoruba': 'yo',
            'persian': 'fa', 'farsi': 'fa', 'pashto': 'ps', 'kurdish': 'ku',
            'armenian': 'hy', 'georgian': 'ka', 'azerbaijani': 'az', 'kazakh': 'kk',
            'nepali': 'ne', 'sinhala': 'si', 'burmese': 'my', 'myanmar': 'my',
            'khmer': 'km', 'cambodian': 'km', 'lao': 'lo', 'laotian': 'lo',
            'filipino': 'tl', 'tagalog': 'tl', 'maltese': 'mt', 'icelandic': 'is',
            'esperanto': 'eo', 'latin': 'la', 'english': 'en'
        }
        if language_name in language_name_to_code:
            return language_name_to_code[language_name]
        for code, name in self.supported_languages.items():
            if language_name == name.lower() or language_name in name.lower() or name.lower().startswith(language_name):
                return code
        for name, code in language_name_to_code.items():
            if language_name == name or language_name in name or name.startswith(language_name):
                return code
        return None

    def detect_language(self, text: str) -> str:
        """Detect the language of given text using Google Translate REST API"""
        try:
            url = f"https://translation.googleapis.com/language/translate/v2/detect?key={self.google_api_key}"
            data = {'q': text}
            response = requests.post(url, data=data)
            if response.status_code == 200:
                result = response.json()
                detected_language = result['data']['detections'][0][0]['language']
                confidence = result['data']['detections'][0][0]['confidence']
                return detected_language if confidence > 0.5 and detected_language in self.supported_languages else 'en'
            return 'en'
        except Exception:
            return 'en'

    def translate_text(self, text: str, target_language: str, source_language: str = None) -> dict:
        """Translate text using Google Translate REST API"""
        try:
            target_lang_code = self.find_language_code(target_language)
            if not target_lang_code:
                return {
                    'success': False,
                    'error': f"Language '{target_language}' not supported",
                    'translated_text': None,
                    'source_language': None,
                    'target_language': target_language
                }
            source_lang_code = self.find_language_code(source_language) if source_language else self.detect_language(text)
            if source_lang_code == target_lang_code:
                return {
                    'success': True,
                    'translated_text': text,
                    'source_language': self.supported_languages.get(source_lang_code, source_lang_code),
                    'target_language': self.supported_languages.get(target_lang_code, target_language),
                    'same_language': True,
                    'target_lang_code': target_lang_code
                }
            url = f"https://translation.googleapis.com/language/translate/v2?key={self.google_api_key}"
            data = {
                'q': text,
                'target': target_lang_code,
                'source': source_lang_code,
                'format': 'text'
            }
            response = requests.post(url, data=data)
            if response.status_code == 200:
                result = response.json()
                translated_text = result['data']['translations'][0]['translatedText']
                history_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'text': text,
                    'target_language': target_language,
                    'translated_text': translated_text,
                    'source_language': self.supported_languages.get(source_lang_code, source_lang_code),
                    'target_language_name': self.supported_languages.get(target_lang_code, target_language)
                }
                self.conversation_history.append(history_entry)
                return {
                    'success': True,
                    'translated_text': translated_text,
                    'source_language': self.supported_languages.get(source_lang_code, source_lang_code),
                    'target_language': self.supported_languages.get(target_lang_code, target_language),
                    'same_language': False,
                    'target_lang_code': target_lang_code
                }
            return {
                'success': False,
                'error': f"Translation API failed: {response.status_code}",
                'translated_text': None,
                'source_language': None,
                'target_language': target_language
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Translation failed: {str(e)}",
                'translated_text': None,
                'source_language': None,
                'target_language': target_language
            }

    def parse_translation_request(self, user_input: str) -> Dict:
        """Parse translation requests using regex patterns"""
        user_input = user_input.strip()
        end_patterns = [
            r'(.+?)\s+translate\s+(?:this|it)\s+(?:in|to)\s+([a-zA-Z\s]+)(?:\.|!|\?|$)',
            r'(.+?)\.\s*translate\s+(?:this|it)\s+(?:in|to)\s+([a-zA-Z\s]+)(?:\.|!|\?|$)',
        ]
        for pattern in end_patterns:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                text_to_translate = match.group(1).strip()
                target_language = match.group(2).strip().rstrip('.!?')
                if self.find_language_code(target_language):
                    return {
                        'is_translation_request': True,
                        'text': text_to_translate,
                        'target_language': target_language,
                        'conversational_response': f"Translating to {target_language.title()}"
                    }
        patterns = [
            r'translate\s+(.+?)\s+(?:to|in|into)\s+([a-zA-Z\s]+?)(?:\.|!|\?|$)',
            r'say\s+(.+?)\s+in\s+([a-zA-Z\s]+?)(?:\.|!|\?|$)',
            r'convert\s+(.+?)\s+to\s+([a-zA-Z\s]+?)(?:\.|!|\?|$)',
            r'how\s+do\s+you\s+say\s+(.+?)\s+in\s+([a-zA-Z\s]+?)(?:\.|!|\?|$)',
            r'what\s+is\s+(.+?)\s+in\s+([a-zA-Z\s]+?)(?:\.|!|\?|$)',
        ]
        for pattern in patterns:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                text_to_translate = match.group(1).strip()
                target_language = match.group(2).strip().rstrip('.!?')
                cleanup_words = ['please', 'can you', 'could you', 'would you', 'will you',
                               'for me', 'the word', 'the phrase', 'this', 'that']
                text_words = text_to_translate.split()
                while text_words and text_words[0].lower() in cleanup_words:
                    text_words.pop(0)
                while text_words and text_words[-1].lower() in cleanup_words:
                    text_words.pop(-1)
                text_to_translate = ' '.join(text_words).strip()
                if text_to_translate and target_language and self.find_language_code(target_language):
                    return {
                        'is_translation_request': True,
                        'text': text_to_translate,
                        'target_language': target_language,
                        'conversational_response': f"Translating '{text_to_translate}' to {target_language.title()}"
                    }
        if any(word in user_input.lower() for word in ['translate', 'translation', 'language']):
            return {
                'is_translation_request': False,
                'text': None,
                'target_language': None,
                'conversational_response': "Try phrases like 'translate hello to Spanish'."
            }
        return {
            'is_translation_request': False,
            'text': None,
            'target_language': None,
            'conversational_response': "Try asking to translate something like 'translate hello to Spanish'."
        }

    def get_supported_languages(self) -> List[Dict]:
        """Return supported languages as a list of dictionaries"""
        return [{'code': code, 'name': name} for code, name in sorted(self.supported_languages.items(), key=lambda x: x[1])]

    def handle_special_commands(self, user_input: str) -> Optional[Dict]:
        """Handle special commands for API use"""
        user_input_lower = user_input.lower().strip()
        if user_input_lower in ["trans", "show translation languages", "show translate languages", "list translation languages", "translation languages"]:
            languages = self.get_supported_languages()
            return {
                'success': True,
                'response_type': 'languages',
                'data': languages
            }
        if user_input_lower in ["help", "commands"]:
            return {
                'success': True,
                'response_type': 'help',
                'data': {
                    'message': (
                        "Available commands:\n"
                        "- Translate text: e.g., 'translate hello to Spanish'\n"
                        "- List languages: 'trans' or 'show translation languages'\n"
                        "- Help: 'help' or 'commands'"
                    )
                }
            }
        return None

    def get_conversation_history(self) -> List[Dict]:
        """Return conversation history"""
        return self.conversation_history
