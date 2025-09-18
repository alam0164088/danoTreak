# dashboard/serializers.py
from rest_framework import serializers
from .models import Category, Phrase

class PhraseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Phrase
        fields = ['id', 'english_text', 'french_text', 'category']
        read_only_fields = ['id']

class CategorySerializer(serializers.ModelSerializer):
    phrases = PhraseSerializer(many=True, read_only=True)

    class Meta:
        model = Category
        fields = ['id', 'name', 'icon', 'phrases']
        read_only_fields = ['id', 'phrases']

    def validate_icon(self, value):
        if value and not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Icon must be a valid URL.")
        return value

class CategoryNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'icon']

    def validate_icon(self, value):
        if value and not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Icon must be a valid URL.")
        return value
