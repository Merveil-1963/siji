# core/utils.py
from django.core.cache import caches

class ChallengeManager:
    def __init__(self, cache_name='default'):
        self.cache = caches[cache_name]
    
    def store_challenge(self, user_id, challenge):
        self.cache.set(f'webauthn_challenge_{user_id}', challenge, timeout=300)
    
    def get_challenge(self, user_id):
        return self.cache.get(f'webauthn_challenge_{user_id}')