from django.contrib import admin

# Register your models here.
from .models import Post, Comment, Like

admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Like)

# Post.objects.create(
#     author=user_instance,
#     title="XSS Test",
#     content="<script>alert('XSS')</script>"
# )