import logging
from django.core.management import call_command

# Configurar logging
logger = logging.getLogger(__name__)

def update_news_job():
    """
    Job agendado para atualizar notícias automaticamente
    """
    try:
        logger.info("Iniciando atualização automática de notícias...")
        call_command('update_news')
        logger.info("Atualização automática concluída com sucesso!")
    except Exception as e:
        logger.error(f"Erro na atualização automática: {str(e)}")