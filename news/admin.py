from django.contrib import admin
from .models import NewsArticle


@admin.register(NewsArticle)
class NewsArticleAdmin(admin.ModelAdmin):
    """Interface administrativa para NewsArticle"""
    
    list_display = ('title_short', 'source', 'category', 'published_date', 'created_at')
    list_filter = ('source', 'category', 'published_date', 'created_at')
    search_fields = ('title', 'description', 'source')
    date_hierarchy = 'published_date'
    ordering = ('-published_date',)
    readonly_fields = ('created_at',)
    
    fieldsets = (
        ('Informações da Notícia', {
            'fields': ('title', 'link', 'description')
        }),
        ('Metadados', {
            'fields': ('source', 'category', 'published_date')
        }),
        ('Sistema', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
    
    def title_short(self, obj):
        """Exibe título truncado"""
        if len(obj.title) > 60:
            return obj.title[:60] + '...'
        return obj.title
    title_short.short_description = 'Título'
    
    def get_queryset(self, request):
        """Otimiza queries"""
        qs = super().get_queryset(request)
        return qs.select_related()