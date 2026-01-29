from apscheduler.schedulers.background import BackgroundScheduler
from django.core.management import call_command
import logging

logger = logging.getLogger(__name__)

def update_news_job():
    """Job para atualizar notícias automaticamente"""
    try:
        logger.info("🔄 Iniciando atualização automática de notícias...")
        call_command('update_news')
        logger.info("✅ Atualização automática concluída!")
    except Exception as e:
        logger.error(f"❌ Erro na atualização: {str(e)}")

def start_scheduler():
    """Inicia o agendador de tarefas"""
    scheduler = BackgroundScheduler()
    
    # Atualizar a cada 1 hora (3600 segundos)
    scheduler.add_job(
        update_news_job,
        'interval',
        hours=1,
        id='update_news_job',
        replace_existing=True
    )
    
    # Ou escolha uma das opções abaixo (descomente):
    
    # A cada 30 minutos:
    # scheduler.add_job(update_news_job, 'interval', minutes=30, id='update_news_job', replace_existing=True)
    
    # Diariamente às 8h da manhã:
    # scheduler.add_job(update_news_job, 'cron', hour=8, minute=0, id='update_news_job', replace_existing=True)
    
    # A cada 6 horas:
    # scheduler.add_job(update_news_job, 'interval', hours=6, id='update_news_job', replace_existing=True)
    
    scheduler.start()
    logger.info("⏰ Agendador de tarefas iniciado com sucesso!")