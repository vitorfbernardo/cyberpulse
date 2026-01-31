"""
Krebs on Security Scraper
Feed RSS: https://krebsonsecurity.com/feed/
Brian Krebs é um jornalista investigativo especializado em cybersecurity
"""

import feedparser
from datetime import datetime
from django.utils import timezone
import pytz


class KrebsClient:
    """Cliente para buscar notícias do Krebs on Security"""
    
    def __init__(self):
        self.feed_url = 'https://krebsonsecurity.com/feed/'
        self.source_name = 'Krebs on Security'
    
    def fetch_news(self, limit=20):
        """
        Busca notícias do feed RSS do Krebs on Security
        
        Args:
            limit (int): Número máximo de notícias
            
        Returns:
            list: Lista de dicionários com notícias
        """
        try:
            feed = feedparser.parse(self.feed_url)
            
            news_list = []
            
            for entry in feed.entries[:limit]:
                # Converter data
                published_date = self._parse_date(entry.get('published_parsed'))
                
                # Detectar categoria
                category = self._detect_category(entry.title, entry.get('summary', ''))
                
                news_item = {
                    'title': entry.title,
                    'link': entry.link,
                    'description': entry.get('summary', entry.get('description', '')),
                    'source': self.source_name,
                    'category': category,
                    'published_date': published_date,
                }
                
                news_list.append(news_item)
            
            return news_list
            
        except Exception as e:
            print(f"Erro ao buscar notícias do Krebs: {str(e)}")
            return []
    
    def _parse_date(self, date_tuple):
        """Converte date tuple para datetime"""
        if date_tuple:
            try:
                dt = datetime(*date_tuple[:6])
                return timezone.make_aware(dt, pytz.UTC)
            except:
                pass
        return timezone.now()
    
    def _detect_category(self, title, description):
        """Detecta categoria baseada no conteúdo"""
        text = (title + ' ' + description).lower()
        
        # Krebs foca bastante em vazamentos e investigações
        if any(word in text for word in ['breach', 'leak', 'stolen', 'exposed', 'hacked']):
            return 'breach'
        elif any(word in text for word in ['ransomware', 'malware', 'trojan', 'backdoor']):
            return 'malware'
        elif any(word in text for word in ['vulnerability', 'cve', 'exploit', 'flaw']):
            return 'vulnerability'
        elif any(word in text for word in ['patch', 'update', 'fix']):
            return 'patch'
        else:
            return 'breach'  # Krebs foca muito em vazamentos


# Instância global
krebs_client = KrebsClient()