def user(request):
    return {"user": getattr(request, "user", None)}
