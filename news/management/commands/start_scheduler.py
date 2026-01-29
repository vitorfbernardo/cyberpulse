from django.core.management.base import BaseCommand
from news.scheduler import start_scheduler

class Command(BaseCommand):
    help = 'Inicia o agendador de tarefas manualmente'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('⏰ Iniciando agendador de tarefas...'))
        start_scheduler()
        self.stdout.write(self.style.SUCCESS('✅ Agendador iniciado com sucesso!'))
        
        # Mantém o processo rodando
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\n⚠️  Agendador interrompido!'))