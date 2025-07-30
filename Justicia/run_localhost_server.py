import os
import sys
from django.core.management import execute_from_command_line
from django.core.management.commands.runserver import Command as RunserverCommand

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Justicia.settings")
    
    # Configuration du serveur HTTPS
    RunserverCommand.default_port = "8000"
    RunserverCommand.default_addr = "localhost"  # Utiliser localhost au lieu de 127.0.0.1
    
    # Ajout des arguments pour le serveur HTTPS
    sys.argv.extend([
        "runserver_plus",
        "--cert-file", "certs/cert.crt",
        "--key-file", "certs/cert.key",
    ])
    
    execute_from_command_line(sys.argv) 