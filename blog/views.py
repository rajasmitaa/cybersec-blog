from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Post, Comment, Like
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login


@login_required
def home(request):
    """
    Show all posts + like/comment counts.
    """
    posts = Post.objects.all().order_by("-created_at")

    # Inject counts for the template
    for p in posts:
        p.like_count = Like.objects.filter(post=p).count()
        p.comment_count = Comment.objects.filter(post=p).count()

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

@login_required
def post_detail(request, post_id):
    """
    Show a single post, like count, comments, and whether user liked it.
    """
    post = get_object_or_404(Post, id=post_id)
    comments = Comment.objects.filter(post=post).order_by("created_at")
    like_count = Like.objects.filter(post=post).count()

    user_liked = False
    if request.user.is_authenticated:
        user_liked = Like.objects.filter(post=post, user=request.user).exists()

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


@login_required
@require_POST
def like_post(request, post_id):
    """
    Like/unlike toggle for posts.
    """
    post = get_object_or_404(Post, id=post_id)
    like, created = Like.objects.get_or_create(post=post, user=request.user)

    if not created:
        like.delete()

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

