from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Post, Comment, Like
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.db.models import Count
from django.contrib.auth import logout
from django.shortcuts import redirect


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


@login_required
def create_post(request):
    """
    Create a post and jump straight to its detail page.
    """
    if request.method == "POST":
        title = request.POST.get("title")
        content = request.POST.get("content")

        if title and content:
            post = Post.objects.create(
                author=request.user,
                title=title,
                content=content,
            )
            return redirect("post_detail", post_id=post.id)

    return render(request, "blog/create_post.html")

#post detail view
@login_required
def post_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    comments = Comment.objects.filter(post=post).order_by("created_at")

    like_count = post.likes.count()
    user_liked = False
    if request.user.is_authenticated:
        user_liked = post.likes.filter(user=request.user).exists()

    context = {
        "post": post,
        "comments": comments,
        "like_count": like_count,
        "user_liked": user_liked,
    }
    return render(request, "blog/post_detail.html", context)


@login_required
@require_POST
def add_comment(request, post_id):
    """
    Add a comment to a post.
    """
    post = get_object_or_404(Post, id=post_id)
    content = request.POST.get("content")

    if content:
        Comment.objects.create(
            post=post,
            user=request.user,
            content=content,
        )

    return redirect("post_detail", post_id=post.id)


"""Like or unlike a post."""

@login_required
@require_POST

def like_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    # Check if user already liked
    existing_like = Like.objects.filter(post=post, user=request.user)

    if existing_like.exists():
        # User already liked → unlike (delete)
        existing_like.delete()
    else:
        # User has not liked yet → create like
        Like.objects.create(post=post, user=request.user)

    return redirect("post_detail", post_id=post.id)

# User signup view
def signup(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("home")
    else:
        form = UserCreationForm()

    return render(request, "registration/signup.html", {"form": form})

@login_required
def profile(request):
    user = request.user
    posts = user.post_set.all()  # All posts created by this user
    return render(request, 'profile.html', {'user': user, 'posts': posts})

def logout_view(request):
    logout(request)
    return redirect('login') 
