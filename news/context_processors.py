from django.utils import timezone
from datetime import timedelta

def system_status(request):
    """
    Context processor para disponibilizar status do sistema em todos os templates
    """
    # IMPORTAÇÃO DENTRO DA FUNÇÃO (evita AppRegistryNotReady)
    from .models import NewsArticle
    
    try:
        # Total de notícias
        total_news = NewsArticle.objects.count()
        
        # Notícias das últimas 24 horas
        last_24h = NewsArticle.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        # Vulnerabilidades recentes (últimas 24h)
        recent_vulnerabilities = NewsArticle.objects.filter(
            category='vulnerability',
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        # Calcular Threat Level
        if recent_vulnerabilities >= 20:
            threat_level = 'ALTO'
            threat_color = 'danger'
            threat_icon = 'fa-exclamation-triangle'
        elif recent_vulnerabilities >= 10:
            threat_level = 'MÉDIO'
            threat_color = 'warning'
            threat_icon = 'fa-exclamation-circle'
        else:
            threat_level = 'BAIXO'
            threat_color = 'success'
            threat_icon = 'fa-shield-alt'
        
        # Calcular última varredura (última notícia adicionada)
        if total_news > 0:
            last_news = NewsArticle.objects.latest('created_at')
            time_diff = timezone.now() - last_news.created_at
            
            if time_diff.total_seconds() < 60:
                last_scan = 'AGORA'
            elif time_diff.total_seconds() < 3600:
                minutes = int(time_diff.total_seconds() / 60)
                last_scan = f'{minutes} min atrás'
            elif time_diff.total_seconds() < 86400:
                hours = int(time_diff.total_seconds() / 3600)
                last_scan = f'{hours}h atrás'
            else:
                days = int(time_diff.total_seconds() / 86400)
                last_scan = f'{days}d atrás'
        else:
            last_scan = 'Nenhuma varredura'
        
        # Verificar se sistema está ativo (teve notícias nas últimas 2 horas)
        recent_activity = NewsArticle.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=2)
        ).exists()
        
        system_online = recent_activity or total_news > 0
        
        # Calcular porcentagem de proteção
        if total_news == 0:
            protection_percent = 0
        else:
            # Proteção baseada em quantas fontes diferentes estão monitoradas
            active_sources = NewsArticle.objects.values('source').distinct().count()
            protection_percent = min(100, active_sources * 25)  # 4 fontes = 100%
        
        return {
            'system_status': {
                'online': system_online,
                'threat_level': threat_level,
                'threat_color': threat_color,
                'threat_icon': threat_icon,
                'last_scan': last_scan,
                'protection_percent': protection_percent,
                'protection_active': protection_percent >= 75,
                'total_threats_24h': recent_vulnerabilities,
                'total_news_24h': last_24h,
                'total_news': total_news,
            }
        }
    except Exception as e:
        # Valores padrão em caso de erro
        return {
            'system_status': {
                'online': True,
                'threat_level': 'BAIXO',
                'threat_color': 'success',
                'threat_icon': 'fa-shield-alt',
                'last_scan': 'Inicializando...',
                'protection_percent': 100,
                'protection_active': True,
                'total_threats_24h': 0,
                'total_news_24h': 0,
                'total_news': 0,
            }
        }