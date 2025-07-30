# Justicia/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse  # Ajoutez cette ligne


urlpatterns = [
    path('', admin.site.urls),
    path('SIJI/', include('SIJI.urls')),
]