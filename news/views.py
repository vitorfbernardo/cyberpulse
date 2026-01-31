from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from datetime import datetime, timedelta
from django.db.models import Count
from django.db.models.functions import TruncDate
import requests
import json
from .threat_intel import threat_intel_client
from django.contrib.auth.decorators import login_required
import re

# Imports dos modelos
from .models import NewsArticle

# Imports dos clientes de vulnerabilidades
from news.bnvd_scraper import bnvd_client
# TODO: Implementar nvd_client futuramente
# from news.nvd_scraper import nvd_client


@login_required
def home(request):
    """Página inicial com dashboard estilo PowerBI"""
    from django.db.models import Count
    from django.db.models.functions import TruncDate
    
    # Datas de referência
    now = timezone.now()
    one_day_ago = now - timedelta(days=1)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)
    
    # KPIs principais
    total_news = NewsArticle.objects.count()
    last_24h = NewsArticle.objects.filter(created_at__gte=one_day_ago).count()
    last_7days = NewsArticle.objects.filter(created_at__gte=seven_days_ago).count()
    last_30days = NewsArticle.objects.filter(created_at__gte=thirty_days_ago).count()
    
    # Notícias recentes para exibição
    recent_news = NewsArticle.objects.order_by('-published_date')[:5]
    
    # Distribuição por categoria (para gráfico de pizza)
    categories_data = []
    categories_labels = []
    categories_count = {}
    
    for category_code, category_name in NewsArticle.CATEGORY_CHOICES:
        count = NewsArticle.objects.filter(category=category_code).count()
        if count > 0:
            categories_count[category_name] = count
            categories_labels.append(category_name)
            categories_data.append(count)
    
    # Top 5 fontes (para gráfico de barras)
    top_sources = NewsArticle.objects.values('source').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    sources_labels = [item['source'] for item in top_sources]
    sources_data = [item['count'] for item in top_sources]
    
    # Evolução temporal dos últimos 30 dias (para gráfico de linha)
    daily_stats = NewsArticle.objects.filter(
        created_at__gte=thirty_days_ago
    ).annotate(
        date=TruncDate('created_at')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    # Se não houver dados em created_at, tentar published_date
    if not daily_stats:
        daily_stats = NewsArticle.objects.filter(
            published_date__gte=thirty_days_ago
        ).annotate(
            date=TruncDate('published_date')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
    
    # Criar dicionário com dados reais
    stats_dict = {stat['date']: stat['count'] for stat in daily_stats}
    
    # Preencher TODOS os 30 dias (com zero quando não houver dados)
    timeline_labels = []
    timeline_data = []
    
    for i in range(30):
        date = (now - timedelta(days=29-i)).date()
        timeline_labels.append(date.strftime('%d/%m'))
        timeline_data.append(stats_dict.get(date, 0))
    
    context = {
        # KPIs
        'total_news': total_news,
        'last_24h': last_24h,
        'last_7days': last_7days,
        'last_30days': last_30days,
        
        # Notícias recentes
        'recent_news': recent_news,
        
        # Dados para gráficos (convertidos para JSON)
        'categories_labels': json.dumps(categories_labels),
        'categories_data': json.dumps(categories_data),
        'categories_count': categories_count,
        
        'sources_labels': json.dumps(sources_labels),
        'sources_data': json.dumps(sources_data),
        
        'timeline_labels': json.dumps(timeline_labels),
        'timeline_data': json.dumps(timeline_data),
    }
    
    return render(request, 'home.html', context)


@login_required
def monitoramento(request):
    """Página de monitoramento com filtros"""
    # Filtros
    category_filter = request.GET.get('category', None)
    source_filter = request.GET.get('source', None)
    
    # Query inicial
    news = NewsArticle.objects.all()
    
    # Aplicar filtros
    if category_filter:
        news = news.filter(category=category_filter)
    if source_filter:
        news = news.filter(source=source_filter)
    
    news = news.order_by('-published_date')[:50]
    
    # Listar fontes disponíveis
    sources = NewsArticle.objects.values_list('source', flat=True).distinct()
    
    context = {
        'page_title': 'Monitoramento',
        'active_tab': 'monitoramento',
        'news': news,
        'categories': NewsArticle.CATEGORY_CHOICES,
        'sources': sources,
        'selected_category': category_filter,
        'selected_source': source_filter,
    }
    
    return render(request, 'monitoramento.html', context)


@login_required
def alertas(request):
    """Página de alertas - notícias críticas"""
    # Notícias de vulnerabilidades críticas dos últimos 7 dias
    seven_days_ago = timezone.now() - timedelta(days=7)
    critical_news = NewsArticle.objects.filter(
        category__in=['vulnerability', 'breach', 'malware'],
        published_date__gte=seven_days_ago
    ).order_by('-published_date')[:20]
    
    context = {
        'page_title': 'Alertas',
        'active_tab': 'alertas',
        'critical_news': critical_news,
    }
    
    return render(request, 'alertas.html', context)


@login_required
def relatorios(request):
    """Página de relatórios com gráficos interativos"""
    # Estatísticas gerais
    total_news = NewsArticle.objects.count()
    last_30_days = NewsArticle.objects.filter(
        created_at__gte=timezone.now() - timedelta(days=30)
    ).count()
    
    # Distribuição por categoria
    categories_stats = []
    for code, name in NewsArticle.CATEGORY_CHOICES:
        count = NewsArticle.objects.filter(category=code).count()
        if count > 0:
            percentage = (count / total_news * 100) if total_news > 0 else 0
            categories_stats.append({
                'code': code,
                'name': name,
                'count': count,
                'percentage': percentage
            })
    
    # Distribuição por fonte
    sources_stats = []
    sources = NewsArticle.objects.values('source').annotate(count=Count('id')).order_by('-count')
    for source in sources:
        count = source['count']
        percentage = (count / total_news * 100) if total_news > 0 else 0
        sources_stats.append({
            'name': source['source'],
            'count': count,
            'percentage': percentage
        })
    
    # Evolução de notícias nos últimos 30 dias (para gráfico de linha)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    # Buscar dados reais
    daily_stats = NewsArticle.objects.filter(
        created_at__gte=thirty_days_ago
    ).annotate(
        date=TruncDate('created_at')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    # Se não houver dados com created_at, tentar com published_date
    if not daily_stats:
        daily_stats = NewsArticle.objects.filter(
            published_date__gte=thirty_days_ago
        ).annotate(
            date=TruncDate('published_date')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
    
    # Criar dicionário com os dados reais
    stats_dict = {}
    if daily_stats:
        for stat in daily_stats:
            stats_dict[stat['date']] = stat['count']
    
    # Preencher TODOS os 30 dias (com zero quando não houver dados)
    dates_list = []
    counts_list = []
    
    for i in range(30):
        date = (timezone.now() - timedelta(days=29-i)).date()
        dates_list.append(date.strftime('%d/%m'))
        counts_list.append(stats_dict.get(date, 0))  # 0 se não houver dados
    
    # Preparar dados para gráfico de pizza (categorias)
    category_labels = [cat['name'] for cat in categories_stats]
    category_counts = [cat['count'] for cat in categories_stats]
    
    # Preparar dados para gráfico de barras (fontes)
    source_labels = [src['name'] for src in sources_stats]
    source_counts = [src['count'] for src in sources_stats]
    
    context = {
        'page_title': 'Relatórios',
        'active_tab': 'relatorios',
        'total_news': total_news,
        'last_30_days': last_30_days,
        'categories_stats': categories_stats,
        'sources_stats': sources_stats,
        # Dados para gráficos (convertidos para JSON)
        'dates_list': json.dumps(dates_list),
        'counts_list': json.dumps(counts_list),
        'category_labels': json.dumps(category_labels),
        'category_counts': json.dumps(category_counts),
        'source_labels': json.dumps(source_labels),
        'source_counts': json.dumps(source_counts),
    }
    
    return render(request, 'relatorios.html', context)


@login_required
def configuracoes(request):
    """Página de configurações"""
    # Informações do sistema
    last_update = NewsArticle.objects.order_by('-created_at').first()
    total_sources = NewsArticle.objects.values('source').distinct().count()
    
    context = {
        'page_title': 'Configurações',
        'active_tab': 'configuracoes',
        'last_update': last_update,
        'total_sources': total_sources,
    }
    
    return render(request, 'configuracoes.html', context)


@login_required
def busca(request):
    """
    Busca de vulnerabilidades no BNVD (e futuramente NVD)
    """
    query = request.GET.get('q', '').strip()
    incluir_bnvd = request.GET.get('incluir_bnvd', '1') == '1'  # Checkbox (padrão: marcado)
    
    resultados = []
    
    if query:
        # TODO: Buscar no NVD (implementar futuramente)
        # try:
        #     nvd_results = nvd_client.search_vulnerabilities(query, limit=10)
        #     resultados.extend(nvd_results)
        # except Exception as e:
        #     messages.error(request, f"Erro ao buscar no NVD: {str(e)}")
        
        # Buscar no BNVD (se checkbox marcado)
        if incluir_bnvd:
            try:
                bnvd_results = bnvd_client.search_vulnerabilities(query, limit=10)
                
                # Converter datas de string para datetime
                for vuln in bnvd_results:
                    if isinstance(vuln.get('published_date'), str):
                        try:
                            vuln['published_date'] = datetime.strptime(vuln['published_date'], '%Y-%m-%d')
                        except:
                            vuln['published_date'] = timezone.now()
                    
                    # Adicionar métodos faltantes para compatibilidade com template
                    vuln['get_category_display'] = vuln.get('severity', 'N/A')
                    vuln['get_category_display_icon'] = '🛡️'
                
                resultados.extend(bnvd_results)
            except Exception as e:
                messages.error(request, f"Erro ao buscar vulnerabilidades: {str(e)}")
    
    context = {
        'query': query,
        'results': resultados,
        'total_results': len(resultados),
        'incluir_bnvd': incluir_bnvd,
    }
    
    return render(request, 'busca.html', context)

# ==================== THREAT INTELLIGENCE ====================



@login_required
def threat_intel_view(request):
    """
    View para Threat Intelligence
    """
    context = {
        'result': None,
        'query': '',
        'query_type': ''
    }
    
    if request.method == 'POST':
        query = request.POST.get('query', '').strip()
        query_type = request.POST.get('query_type', 'auto')
        
        if query:
            context['query'] = query
            
            # Auto-detectar tipo se não especificado
            if query_type == 'auto':
                query_type = detect_query_type(query)
            
            context['query_type'] = query_type
            
            # Executar análise baseada no tipo
            if query_type == 'ip':
                result = threat_intel_client.analyze_ip(query)
            elif query_type == 'hash':
                result = threat_intel_client.analyze_hash(query)
            elif query_type == 'domain':
                result = threat_intel_client.analyze_domain(query)
            else:
                result = {'error': 'Tipo de consulta não reconhecido'}
            
            context['result'] = result
    
    return render(request, 'threat_intel.html', context)


def detect_query_type(query):
    """
    Detecta automaticamente o tipo de consulta
    """
    query_clean = query.strip()
    
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, query_clean):
        return 'ip'
    
    # Hash (MD5: 32, SHA1: 40, SHA256: 64)
    if re.match(r'^[a-fA-F0-9]{32}$', query_clean):
        return 'hash'  # MD5
    if re.match(r'^[a-fA-F0-9]{40}$', query_clean):
        return 'hash'  # SHA1
    if re.match(r'^[a-fA-F0-9]{64}$', query_clean):
        return 'hash'  # SHA256
    
    # Domain
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if re.match(domain_pattern, query_clean):
        return 'domain'
    
    return 'unknown'