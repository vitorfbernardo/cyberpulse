from django.core.management.base import BaseCommand
from django.utils import timezone
from news.models import NewsArticle
import feedparser
from datetime import datetime
import re


class Command(BaseCommand):
    help = 'Busca e atualiza notícias de cybersecurity de múltiplas fontes RSS'

    # Lista de fontes RSS de cybersecurity
    RSS_FEEDS = [
        {
            'url': 'https://feeds.feedburner.com/TheHackersNews',
            'source': 'The Hacker News'
        },
        {
            'url': 'https://www.bleepingcomputer.com/feed/',
            'source': 'Bleeping Computer'
        },
        {
            'url': 'https://threatpost.com/feed/',
            'source': 'Threatpost'
        },
    ]

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🔄 Iniciando busca de notícias de cybersecurity...'))
        self.stdout.write('')

        total_found = 0
        total_new = 0
        total_duplicates = 0

        for feed_info in self.RSS_FEEDS:
            self.stdout.write(f"✅ Processando: {feed_info['source']}")
            
            try:
                # Parse do RSS feed
                feed = feedparser.parse(feed_info['url'])
                
                if feed.bozo:
                    self.stdout.write(
                        self.style.WARNING(f"⚠️  Aviso ao processar {feed_info['source']}: {feed.bozo_exception}")
                    )
                
                # Processar cada entrada do feed
                for entry in feed.entries:
                    total_found += 1
                    
                    # Extrair dados da notícia
                    title = entry.get('title', 'Sem título')
                    link = entry.get('link', '')
                    description = entry.get('summary', entry.get('description', ''))
                    
                    # Limpar HTML da descrição
                    description = self.clean_html(description)
                    
                    # Data de publicação
                    published_date = self.parse_date(entry)
                    
                    # Categoria automática baseada no conteúdo
                    category = self.detect_category(title, description)
                    
                    # Verificar se já existe (evitar duplicatas)
                    if not NewsArticle.objects.filter(link=link).exists():
                        NewsArticle.objects.create(
                            title=title,
                            link=link,
                            description=description,
                            source=feed_info['source'],
                            category=category,
                            published_date=published_date
                        )
                        total_new += 1
                        self.stdout.write(f"   📰 Nova: {title[:60]}...")
                    else:
                        total_duplicates += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ Erro ao processar {feed_info['source']}: {str(e)}")
                )
        
        # Resumo final
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('━' * 50))
        self.stdout.write(self.style.SUCCESS('📊 Resumo da atualização:'))
        self.stdout.write(f"   • Notícias encontradas: {total_found}")
        self.stdout.write(f"   • Novas notícias: {total_new}")
        self.stdout.write(f"   • Duplicatas ignoradas: {total_duplicates}")
        self.stdout.write(self.style.SUCCESS('✅ Atualização concluída com sucesso!'))

    def clean_html(self, text):
        """Remove tags HTML do texto"""
        clean = re.compile('<.*?>')
        return re.sub(clean, '', text).strip()

    def parse_date(self, entry):
        """Converte a data do feed para datetime"""
        try:
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                return datetime(*entry.published_parsed[:6])
            elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                return datetime(*entry.updated_parsed[:6])
        except:
            pass
        return timezone.now()

    def detect_category(self, title, description):
        """Detecta a categoria baseada em palavras-chave"""
        text = (title + ' ' + description).lower()
        
        if any(word in text for word in ['vulnerability', 'vulnerabilidade', 'cve', 'exploit', 'zero-day']):
            return 'vulnerability'
        elif any(word in text for word in ['breach', 'vazamento', 'leak', 'hack', 'attack', 'ataque']):
            return 'breach'
        elif any(word in text for word in ['malware', 'ransomware', 'virus', 'trojan', 'backdoor']):
            return 'malware'
        elif any(word in text for word in ['patch', 'update', 'fix', 'correção']):
            return 'patch'
        else:
            return 'general'