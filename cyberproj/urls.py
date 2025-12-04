from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from blog import views as blog_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # 🔹 Custom logout view (must be BEFORE the auth include to override default)
    path('accounts/logout/', blog_views.logout_view, name='logout'),

    # 🔹 Django’s built-in login / password reset / etc.
    path('accounts/', include('django.contrib.auth.urls')),

    # 🔹 Redirect root → login page
    path('', RedirectView.as_view(url='/accounts/login/', permanent=False)),

    # 🔹 Blog app under /home/
    path('home/', include('blog.urls')),

    # 🔹 Signup view
    path('accounts/signup/', blog_views.signup, name='signup'),
]
