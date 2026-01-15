from django.urls import path, include
from . import views
from . import views_auth



urlpatterns = [
    path('signup/', views_auth.signup, name='signup'),
    path('home/', views.home, name='home'),
    path('post/new/', views.create_post, name='create_post'),
    path('post/<int:post_id>/', views.post_detail, name='post_detail'),
    path('post/<int:post_id>/comment/', views.add_comment, name='add_comment'),
    path('post/<int:post_id>/like/', views.like_post, name='like_post'),
    path('profile/', views.profile, name='profile'),
    path("forgot-password/", views.forgot_password, name="forgot_password"),  # ADDED
    

]
