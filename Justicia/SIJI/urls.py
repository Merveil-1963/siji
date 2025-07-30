from django.contrib import admin
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),  # accueil racine
    path('admin/', admin.site.urls),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin-panel/', views.admin_panel, name='admin_panel'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    
    # URLs pour la gestion du profil
    path('update-profile/', views.update_profile, name='update_profile'),
    path('change-password/', views.change_password, name='change_password'),
    path('update-notifications/', views.update_notifications, name='update_notifications'),
    
    # URLs pour WebAuthn
    path('webauthn/register/begin/', views.webauthn_register_begin, name='webauthn_register_begin'),
    path('webauthn/register/complete/', views.webauthn_register_complete, name='webauthn_register_complete'),
    path('webauthn/authenticate/begin/', views.webauthn_authenticate_begin, name='webauthn_authenticate_begin'),
    path('webauthn/authenticate/complete/', views.webauthn_authenticate_complete, name='webauthn_authenticate_complete'),
    path('webauthn/manage/', views.webauthn_manage, name='webauthn_manage'),
]
