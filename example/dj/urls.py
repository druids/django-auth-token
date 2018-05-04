import django
from django.conf.urls import include, url
from django.conf import settings


urlpatterns = []


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
