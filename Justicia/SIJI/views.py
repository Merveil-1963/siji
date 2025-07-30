from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.http import JsonResponse
import json
import base64
import os
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from django.contrib.auth import get_user_model
from .forms import SignUpForm
from django.http import JsonResponse
from django.conf import settings

User = get_user_model()

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        return redirect('login')

def register(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, 'Vous avez été déconnecté avec succès.')
    return redirect('home')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@login_required
def admin_panel(request):
    users = User.objects.all()
    return render(request, 'admin_panel.html', {'users': users})

@login_required
def delete_user(request, user_id):
    if request.method == 'POST':
        user = User.objects.get(id=user_id)
        user.delete()
        return redirect('admin_panel')
    return redirect('admin_panel')

# WebAuthn views
@login_required
def webauthn_manage(request):
    return render(request, 'webauthn/manage.html')

@login_required
def webauthn_register_begin(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Vérifier le token CSRF
        if not request.headers.get('X-CSRFToken'):
            return JsonResponse({'error': 'CSRF token missing'}, status=403)
        
        # Générer un challenge aléatoire
        challenge = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Stocker le challenge dans la session
        request.session['webauthn_challenge'] = challenge
        
        # Utiliser localhost comme RP ID
        rp_id = "localhost"
        origin = "https://localhost:8000"
        
        print(f"Using RP ID: {rp_id}")
        print(f"Using Origin: {origin}")
        
        # Préparer les options pour le navigateur
        options = {
            'publicKey': {
                'challenge': challenge,
                'rp': {
                    'name': 'Justicia',
                    'id': rp_id,
                },
                'user': {
                    'id': base64.b64encode(str(request.user.id).encode()).decode('utf-8'),
                    'name': request.user.username,
                    'displayName': request.user.username,
                },
                'pubKeyCredParams': [
                    {'type': 'public-key', 'alg': -7},  # ES256
                    {'type': 'public-key', 'alg': -257},  # RS256
                ],
                'timeout': 60000,
                'attestation': 'none',
                'authenticatorSelection': {
                    'authenticatorAttachment': 'platform',
                    'userVerification': 'preferred',
                    'requireResidentKey': False,
                },
                'excludeCredentials': []
            }
        }
        
        print(f"WebAuthn options: {options}")
        return JsonResponse(options)
    except Exception as e:
        print(f"Error in webauthn_register_begin: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def webauthn_register_complete(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        # Vérifier que le challenge correspond
        stored_challenge = request.session.get('webauthn_challenge')
        if not stored_challenge:
            return JsonResponse({'error': 'No challenge found'}, status=400)
        
        # Ici, vous devriez vérifier la signature et l'attestation
        # Pour l'instant, nous retournons simplement un succès
        
        # Nettoyer la session
        del request.session['webauthn_challenge']
        
        return JsonResponse({'status': 'success'})
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def update_profile(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        
        # Vérifier si le nom d'utilisateur est déjà pris
        if User.objects.exclude(pk=request.user.pk).filter(username=username).exists():
            messages.error(request, 'Ce nom d\'utilisateur est déjà pris.')
            return redirect('dashboard')
        
        # Vérifier si l'email est valide
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Veuillez entrer une adresse email valide.')
            return redirect('dashboard')
        
        # Vérifier si l'email est déjà pris
        if User.objects.exclude(pk=request.user.pk).filter(email=email).exists():
            messages.error(request, 'Cette adresse email est déjà utilisée.')
            return redirect('dashboard')
        
        # Mettre à jour le profil
        user = request.user
        user.username = username
        user.email = email
        user.save()
        
        messages.success(request, 'Votre profil a été mis à jour avec succès.')
        return redirect('dashboard')
    
    return redirect('dashboard')

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Vérifier le mot de passe actuel
        if not check_password(current_password, request.user.password):
            messages.error(request, 'Le mot de passe actuel est incorrect.')
            return redirect('dashboard')
        
        # Vérifier que les nouveaux mots de passe correspondent
        if new_password != confirm_password:
            messages.error(request, 'Les nouveaux mots de passe ne correspondent pas.')
            return redirect('dashboard')
        
        # Vérifier la complexité du mot de passe
        if len(new_password) < 8:
            messages.error(request, 'Le mot de passe doit contenir au moins 8 caractères.')
            return redirect('dashboard')
        
        # Changer le mot de passe
        request.user.set_password(new_password)
        request.user.save()
        
        # Reconnecter l'utilisateur
        login(request, request.user)
        
        messages.success(request, 'Votre mot de passe a été changé avec succès.')
        return redirect('dashboard')
    
    return redirect('dashboard')

@login_required
def update_notifications(request):
    if request.method == 'POST':
        email_notifications = request.POST.get('email_notifications') == 'on'
        sms_notifications = request.POST.get('sms_notifications') == 'on'
        
        # Ici, vous pouvez ajouter la logique pour sauvegarder les préférences de notification
        # Par exemple, dans un modèle UserProfile ou dans les paramètres utilisateur
        
        messages.success(request, 'Vos préférences de notification ont été mises à jour.')
        return redirect('dashboard')
    
    return redirect('dashboard')

@login_required
def webauthn_authenticate_begin(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Générer un challenge aléatoire
    challenge = base64.b64encode(os.urandom(32)).decode('utf-8')
    
    # Stocker le challenge dans la session
    request.session['webauthn_challenge'] = challenge
    
    # Préparer les options pour le navigateur
    options = {
        'publicKey': {
            'challenge': challenge,
            'rpId': request.get_host().split(':')[0],
            'allowCredentials': [
                # Ici, vous devriez inclure les identifiants enregistrés de l'utilisateur
                # Pour l'instant, nous retournons un tableau vide
            ],
            'userVerification': 'preferred',
            'timeout': 60000,
        }
    }
    
    return JsonResponse(options)

@login_required
def webauthn_authenticate_complete(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        # Vérifier que le challenge correspond
        stored_challenge = request.session.get('webauthn_challenge')
        if not stored_challenge:
            return JsonResponse({'error': 'No challenge found'}, status=400)
        
        # Ici, vous devriez vérifier la signature et l'authentification
        # Pour l'instant, nous retournons simplement un succès
        
        # Nettoyer la session
        del request.session['webauthn_challenge']
        
        return JsonResponse({'status': 'success'})
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)