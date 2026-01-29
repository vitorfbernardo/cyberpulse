from django.apps import AppConfig
import os

class NewsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'news'
    
    def ready(self):
        """Executa quando a aplicação Django está pronta"""
        # Inicia o scheduler apenas uma vez (evita duplicação em modo debug)
        if os.environ.get('RUN_MAIN') == 'true':
            from news.scheduler import start_scheduler
            start_scheduler()