from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from blog import views as blog_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # Django’s built-in login/logout/password reset
    path('accounts/', include('django.contrib.auth.urls')),

    # Redirect root → login page
    path('', RedirectView.as_view(url='/accounts/login/', permanent=False)),

    # Blog app
    path('home/', include('blog.urls')),

    # Signup page
    path('accounts/signup/', blog_views.signup, name='signup'),
]

