from django.apps import AppConfig
import os


class NewsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'news'
    
    def ready(self):
        """
        Executado quando o app Django é carregado
        Inicia o agendador automático
        """
        # CRITICAL: Evitar duplicação no autoreloader do Django
        if os.environ.get('RUN_MAIN') == 'true':
            try:
                from . import scheduler
                scheduler.start_scheduler()
            except Exception as e:
                print(f"❌ Erro ao iniciar scheduler: {str(e)}")
                import traceback
                traceback.print_exc()