from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import os

class Command(BaseCommand):
    help = 'Cria superusuário se não existir'

    def handle(self, *args, **options):
        User = get_user_model()
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@cyberpulse.com')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'senha123')
        
        if not User.objects.filter(username=username).exists():
            User.objects.create_superuser(username, email, password)
            self.stdout.write(self.style.SUCCESS(f'Superusuário {username} criado com sucesso!'))
        else:
            self.stdout.write(self.style.WARNING(f'Superusuário {username} já existe!'))