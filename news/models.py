from django.db import models
from django.utils import timezone


class NewsArticle(models.Model):
    """Modelo para armazenar notícias de cybersecurity"""
    
    CATEGORY_CHOICES = [
        ('vulnerability', 'Vulnerabilidade'),
        ('breach', 'Vazamento de Dados'),
        ('malware', 'Malware'),
        ('patch', 'Patch/Atualização'),
        ('general', 'Geral'),
    ]
    
    title = models.CharField(max_length=500, verbose_name="Título")
    link = models.URLField(max_length=1000, unique=True, verbose_name="Link da Notícia")
    description = models.TextField(verbose_name="Descrição")
    source = models.CharField(max_length=200, verbose_name="Fonte")
    category = models.CharField(
        max_length=20, 
        choices=CATEGORY_CHOICES, 
        default='general',
        verbose_name="Categoria"
    )
    published_date = models.DateTimeField(verbose_name="Data de Publicação")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Adicionado em")
    
    class Meta:
        verbose_name = "Notícia"
        verbose_name_plural = "Notícias"
        ordering = ['-published_date']
        indexes = [
            models.Index(fields=['-published_date']),
            models.Index(fields=['category']),
            models.Index(fields=['source']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.source}"
    
    def get_category_display_icon(self):
        """Retorna um ícone para a categoria"""
        icons = {
            'vulnerability': '🔓',
            'breach': '⚠️',
            'malware': '🦠',
            'patch': '🔧',
            'general': '📰',
        }
        return icons.get(self.category, '📰')