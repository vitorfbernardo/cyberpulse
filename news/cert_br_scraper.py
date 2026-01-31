"""
CERT.br Scraper - Centro de Estudos, Resposta e Tratamento de Incidentes de Segurança no Brasil
Feed RSS: https://www.cert.br/feed/
"""

import feedparser
from datetime import datetime
from django.utils import timezone
import pytz


class CertBrClient:
    """Cliente para buscar notícias do CERT.br"""
    
    def __init__(self):
        self.feed_url = 'https://cert.br/rss/certbr-rss.xml'
        self.source_name = 'CERT.br'
    
    def fetch_news(self, limit=20):
        """
        Busca notícias do feed RSS do CERT.br
        
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
                
                # Detectar categoria baseada no título/descrição
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
            print(f"Erro ao buscar notícias do CERT.br: {str(e)}")
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
        
        # Palavras-chave por categoria
        if any(word in text for word in ['vulnerabilidade', 'vulnerability', 'cve', 'falha', 'exploit']):
            return 'vulnerability'
        elif any(word in text for word in ['vazamento', 'breach', 'leak', 'dados expostos']):
            return 'breach'
        elif any(word in text for word in ['malware', 'ransomware', 'trojan', 'vírus', 'virus']):
            return 'malware'
        elif any(word in text for word in ['patch', 'atualização', 'update', 'correção']):
            return 'patch'
        else:
            return 'general'


# Instância global
cert_br_client = CertBrClient()