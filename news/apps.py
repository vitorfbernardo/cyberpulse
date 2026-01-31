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
        import sys
        
        # Evitar duplicação no runserver (desenvolvimento)
        # No gunicorn (produção), RUN_MAIN não existe, então passa direto
        if os.environ.get('RUN_MAIN') != 'false' and 'migrate' not in sys.argv:
            try:
                from . import scheduler
                scheduler.start_scheduler()
            except Exception as e:
                print(f"❌ Erro ao iniciar scheduler: {str(e)}")
                import traceback
                traceback.print_exc()