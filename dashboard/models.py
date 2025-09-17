# dashboard/models.py
from django.db import models

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    icon = models.URLField(blank=True, null=True)  # Fixed: Changed URLFieldField to URLField

    def __str__(self):
        return self.name

class Phrase(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='phrases')
    english_text = models.CharField(max_length=255)
    french_text = models.CharField(max_length=255)

    def __str__(self):
        return self.english_text