from django.core.management.base import BaseCommand
from django.utils import timezone
from news.models import NewsArticle

# Importar TODAS as 5 fontes
from news.cert_br_scraper import cert_br_client
from news.cisa_scraper import cisa_client
from news.krebs_scraper import krebs_client
from news.hackernews_scraper import hackernews_client
from news.bleepingcomputer_scraper import bleepingcomputer_client


class Command(BaseCommand):
    help = 'Atualiza notícias de cybersecurity de múltiplas fontes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=20,
            help='Número máximo de notícias por fonte'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        
        self.stdout.write(self.style.SUCCESS('🚀 Iniciando atualização de notícias...'))
        self.stdout.write('')
        
        total_created = 0
        total_duplicates = 0
        
        # Lista de clientes (AGORA COM 5 FONTES!)
        sources = [
            ('CERT.br 🇧🇷', cert_br_client),
            ('CISA 🇺🇸', cisa_client),
            ('Krebs on Security', krebs_client),
            ('The Hacker News', hackernews_client),
            ('Bleeping Computer', bleepingcomputer_client),
        ]
        
        # Buscar de cada fonte
        for source_name, client in sources:
            self.stdout.write(f'📡 Buscando de {source_name}...')
            
            try:
                news_list = client.fetch_news(limit=limit)
                created, duplicates = self._save_news(news_list)
                
                total_created += created
                total_duplicates += duplicates
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'   ✅ {created} novas | ⚠️  {duplicates} duplicadas'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'   ❌ Erro: {str(e)}')
                )
            
            self.stdout.write('')
        
        # Resumo final
        self.stdout.write('━' * 50)
        self.stdout.write(self.style.SUCCESS(f'✅ TOTAL: {total_created} notícias adicionadas'))
        self.stdout.write(self.style.WARNING(f'⚠️  TOTAL: {total_duplicates} duplicadas (ignoradas)'))
        self.stdout.write('━' * 50)
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('🎉 Atualização concluída!'))

    def _save_news(self, news_list):
        """Salva notícias no banco, evitando duplicatas"""
        created = 0
        duplicates = 0
        
        for news_data in news_list:
            # Verificar se já existe (mesmo link)
            if NewsArticle.objects.filter(link=news_data['link']).exists():
                duplicates += 1
                continue
            
            try:
                NewsArticle.objects.create(**news_data)
                created += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Erro ao salvar: {str(e)}')
                )
        
        return created, duplicates