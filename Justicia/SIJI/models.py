# SIJI/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    # Champs personnalisés (exemple)
    biometric_enabled = models.BooleanField(default=False)

    # Évitez de redéfinir les champs existants comme 'username' ou 'email'

class BiometricCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=255)
    registered_at = models.DateTimeField(auto_now_add=True)

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)
    device_name = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"{self.user.username}'s {self.device_name or 'WebAuthn device'}"