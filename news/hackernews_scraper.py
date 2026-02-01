import feedparser
from datetime import datetime
from django.utils import timezone
import time

class TheHackerNewsClient:
    """Cliente para buscar notícias do The Hacker News"""
    
    def __init__(self):
        self.rss_url = 'https://feeds.feedburner.com/TheHackersNews'
        self.source_name = 'The Hacker News'
    
    def fetch_news(self, limit=20):
        """
        Busca notícias do RSS feed do The Hacker News
        
        Args:
            limit (int): Número máximo de notícias a retornar
            
        Returns:
            list: Lista de dicionários com dados das notícias
        """
        try:
            feed = feedparser.parse(self.rss_url)
            
            if not feed.entries:
                return []
            
            news_list = []
            
            for entry in feed.entries[:limit]:
                try:
                    # Parse da data de publicação
                    published_date = self._parse_date(entry.get('published'))
                    
                    # Extrair descrição (resumo)
                    description = entry.get('summary', '')
                    if len(description) > 500:
                        description = description[:497] + '...'
                    
                    # Categorizar baseado no conteúdo
                    category = self._categorize_news(entry.get('title', ''), description)
                    
                    news_data = {
                        'title': entry.get('title', 'Sem título'),
                        'link': entry.get('link', ''),
                        'description': description,
                        'published_date': published_date,
                        'source': self.source_name,
                        'category': category,
                    }
                    
                    news_list.append(news_data)
                    
                except Exception as e:
                    print(f"Erro ao processar entrada: {str(e)}")
                    continue
            
            return news_list
            
        except Exception as e:
            print(f"Erro ao buscar feed do The Hacker News: {str(e)}")
            return []
    
    def _parse_date(self, date_string):
        """Converte string de data para datetime"""
        if not date_string:
            return timezone.now()
        
        try:
            # Parse da estrutura time.struct_time do feedparser
            time_struct = feedparser._parse_date(date_string)
            if time_struct:
                return datetime(*time_struct[:6])
            return timezone.now()
        except:
            return timezone.now()
    
    def _categorize_news(self, title, description):
        """Categoriza a notícia baseado em palavras-chave"""
        text = (title + ' ' + description).lower()
        
        # Palavras-chave para cada categoria
        if any(word in text for word in ['vulnerability', 'cve-', 'exploit', 'patch', 'zero-day', 'bug']):
            return 'vulnerability'
        elif any(word in text for word in ['breach', 'hacked', 'data leak', 'exposed', 'stolen']):
            return 'breach'
        elif any(word in text for word in ['malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'spyware']):
            return 'malware'
        elif any(word in text for word in ['phishing', 'scam', 'fraud', 'social engineering']):
            return 'threat'
        elif any(word in text for word in ['update', 'release', 'version', 'security patch']):
            return 'update'
        else:
            return 'general'

# Instância global do cliente
hackernews_client = TheHackerNewsClient()