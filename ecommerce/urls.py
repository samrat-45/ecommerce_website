from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include('e_app.urls')),
    path("auth/", include('e_app_auth.urls')),
    
]
