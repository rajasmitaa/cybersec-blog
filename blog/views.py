from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.contrib.auth import login, logout
from django.db.models import Count
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import models

from .models import Post, Comment, Like, SecurityQuestion
from .forms import PostForm, SignUpForm


# ===================== HOME =====================

@login_required
def home(request):
    posts = (
        Post.objects.all()
        .annotate(
            like_count=Count("likes", distinct=True),
            comment_count=Count("comment", distinct=True),
        )
        .order_by("-created_at")
    )
    return render(request, "home.html", {"posts": posts})


# ===================== CREATE POST =====================

@login_required
def create_post(request):
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            return redirect("home")
    else:
        form = PostForm()

    return render(request, "blog/create_post.html", {"form": form})


# ===================== POST DETAIL =====================

@login_required
def post_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    comments = Comment.objects.filter(post=post).order_by("created_at")

    like_count = post.likes.count()
    user_liked = post.likes.filter(user=request.user).exists()

    context = {
        "post": post,
        "comments": comments,
        "like_count": like_count,
        "user_liked": user_liked,
    }
    return render(request, "blog/post_detail.html", context)


# ===================== ADD COMMENT =====================

@login_required
@require_POST
def add_comment(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    content = request.POST.get("content")

    if content:
        Comment.objects.create(
            post=post,
            user=request.user,
            content=content,
        )

    return redirect("post_detail", post_id=post.id)


# ===================== LIKE / UNLIKE =====================

@login_required
@require_POST
def like_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    existing_like = Like.objects.filter(post=post, user=request.user)

    if existing_like.exists():
        existing_like.delete()
    else:
        Like.objects.create(post=post, user=request.user)

    return redirect("home")


# ===================== SIGNUP =====================

def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()

            SecurityQuestion.objects.create(
                user=user,
                question=form.cleaned_data["security_question"],
                answer=form.cleaned_data["security_answer"],
            )

            login(request, user)
            return redirect("home")
    else:
        form = SignUpForm()

    return render(request, "registration/signup.html", {"form": form})


# ===================== PROFILE =====================

@login_required
def profile(request):
    posts = Post.objects.filter(author=request.user).order_by("-created_at")
    return render(request, "profile.html", {"posts": posts})


# ===================== LOGOUT =====================

def logout_view(request):
    logout(request)
    return redirect("login")


# ===================== FORGOT PASSWORD (OPTION 2: SINGLE VIEW) =====================

QUESTION_MAP = {
    "pet": "What is your first pet's name?",
    "mother": "What is your mother's maiden name?",
    "ex": "What is the name of the person your ex is currently dating?",
}

def forgot_password(request):
    if request.method == "POST":

        # ---------- STAGE 1: USERNAME / EMAIL ----------
        if "username" in request.POST and "answer" not in request.POST:
            input_value = request.POST.get("username", "").strip()

            try:
                user = User.objects.get(
                    models.Q(username__iexact=input_value)
                    | models.Q(email__iexact=input_value)
                )

                security = SecurityQuestion.objects.get(user=user)

                return render(
                    request,
                    "registration/verify_question.html",
                    {
                        "username": user.username,
                        "question": QUESTION_MAP.get(
                            security.question, "Security Question"
                        ),
                    },
                )

            except User.DoesNotExist:
                messages.error(request, "Username or email not found")

            except SecurityQuestion.DoesNotExist:
                messages.error(request, "Security question not set")

        # ---------- STAGE 2: ANSWER + NEW PASSWORD ----------
        elif "answer" in request.POST:
            username = request.POST.get("username")
            answer = request.POST.get("answer", "").strip()
            new_password = request.POST.get("password", "").strip()

            try:
                user = User.objects.get(username=username)
                security = SecurityQuestion.objects.get(user=user)

                if answer.lower() == security.answer.lower():
                    user.set_password(new_password)
                    user.save()
                    messages.success(
                        request, "Password reset successful. Please log in."
                    )
                    return redirect("login")
                else:
                    messages.error(request, "Incorrect answer")

                return render(
                    request,
                    "registration/verify_question.html",
                    {
                        "username": username,
                        "question": QUESTION_MAP.get(
                            security.question, "Security Question"
                        ),
                    },
                )

            except (User.DoesNotExist, SecurityQuestion.DoesNotExist):
                messages.error(request, "Something went wrong. Try again.")

    return render(request, "registration/forgot_password.html")
