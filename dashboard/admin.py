# dashboard/admin.py
from django.contrib import admin
from .models import Category, Phrase

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'icon']  # অ্যাডমিনে ক্যাটাগরির তালিকায় এই ফিল্ডগুলো দেখাবে
    search_fields = ['name']  # নাম দিয়ে সার্চ করার সুবিধা
    list_filter = ['name']  # নাম দিয়ে ফিল্টার করার সুবিধা

@admin.register(Phrase)
class PhraseAdmin(admin.ModelAdmin):
    list_display = ['id', 'english_text', 'french_text', 'category']  # ফ্রেজের তালিকায় এই ফিল্ডগুলো দেখাবে
    search_fields = ['english_text', 'french_text']  # ইংরেজি বা ফ্রেঞ্চ টেক্সট দিয়ে সার্চ
    list_filter = ['category']  # ক্যাটাগরি দিয়ে ফিল্টার