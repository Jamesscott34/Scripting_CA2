"""Views for the CA2 banking app.

The secure / insecure behaviour will be implemented in a later step; for now,
we provide basic authenticated views and templates.
"""

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    return render(request, "app/dashboard.html")


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    return render(request, "app/profile.html")


@login_required
def search(request: HttpRequest) -> HttpResponse:
    query = request.GET.get("q", "")
    context = {"query": query}
    return render(request, "app/search.html", context)



