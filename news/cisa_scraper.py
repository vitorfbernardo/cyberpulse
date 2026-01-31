"""
CISA Scraper - Cybersecurity & Infrastructure Security Agency (EUA)
Feed RSS: https://www.cisa.gov/cybersecurity-advisories/all.xml
"""

import feedparser
from datetime import datetime
from django.utils import timezone
import pytz


class CisaClient:
    """Cliente para buscar alertas da CISA"""
    
    def __init__(self):
        self.feed_url = 'https://www.cisa.gov/cybersecurity-advisories/all.xml'
        self.source_name = 'CISA'
    
    def fetch_news(self, limit=20):
        """
        Busca alertas do feed RSS da CISA
        
        Args:
            limit (int): Número máximo de alertas
            
        Returns:
            list: Lista de dicionários com alertas
        """
        try:
            feed = feedparser.parse(self.feed_url)
            
            news_list = []
            
            for entry in feed.entries[:limit]:
                # Converter data
                published_date = self._parse_date(entry.get('published_parsed'))
                
                # CISA foca principalmente em vulnerabilidades
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
            print(f"Erro ao buscar alertas da CISA: {str(e)}")
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
        
        if any(word in text for word in ['vulnerability', 'cve', 'exploit', 'flaw']):
            return 'vulnerability'
        elif any(word in text for word in ['breach', 'leak', 'exposure', 'compromised']):
            return 'breach'
        elif any(word in text for word in ['malware', 'ransomware', 'trojan', 'backdoor']):
            return 'malware'
        elif any(word in text for word in ['patch', 'update', 'fix', 'mitigation']):
            return 'patch'
        else:
            return 'vulnerability'  # CISA foca em vulnerabilidades


# Instância global
cisa_client = CisaClient()