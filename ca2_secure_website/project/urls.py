"""Root URL configuration for the CA2 banking project."""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.static import serve as static_serve

from app.views import CustomLoginView, admin_dashboard

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/login/", CustomLoginView.as_view(), name="login"),
    path("accounts/", include("django.contrib.auth.urls")),
    path("admin-dashboard/", admin_dashboard, name="admin_dashboard"),
    path("", include("app.urls")),
    # Explicit static handler for CA2 demos – serves from `static/` directory.
    path(
        "static/<path:path>",
        static_serve,
        {"document_root": settings.STATICFILES_DIRS[0]},
    ),
]

# James Scott (sba24070)
