from django.db import models

# Create your models here.
from django.contrib.auth.models import User

#post model

class Post(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.FileField(upload_to="uploads/") #helps to make content vulnerable by allowing to upload any sort of files without filtering
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    
#comment model

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment by {self.user.username}'

#like model

class Like(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f'Like by {self.user.username}'
