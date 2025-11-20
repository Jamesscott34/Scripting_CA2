"""Root URL configuration for the CA2 banking project."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("", include("app.urls")),
]

# Serve static files for CA2 demos directly from the `static/` folder,
# regardless of DEBUG. This avoids needing collectstatic in development.
urlpatterns += static(
    settings.STATIC_URL,
    document_root=settings.STATICFILES_DIRS[0],
    insecure=True,
)

