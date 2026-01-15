from django import forms
from .models import Post
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['title', 'content', 'image']  # 👈 added image


SECURITY_QUESTIONS = [  # ADDED
    ("pet", "What is your first pet's name?"),
    ("mother", "What is your mother's maiden name?"),
    ("ex", "What is the name of the person your ex is currently dating?"),
]

class SignUpForm(UserCreationForm):
    security_question = forms.ChoiceField(choices=SECURITY_QUESTIONS)  # ADDED
    security_answer = forms.CharField(max_length=255)  # ADDED

    class Meta:
        model = User
        fields = ("username", "password1", "password2", "security_question", "security_answer")  # CHANGED