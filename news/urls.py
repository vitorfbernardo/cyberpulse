from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('monitoramento/', views.monitoramento, name='monitoramento'),
    path('alertas/', views.alertas, name='alertas'),
    path('relatorios/', views.relatorios, name='relatorios'),
    path('configuracoes/', views.configuracoes, name='configuracoes'),
    path('busca/', views.busca, name='busca'),  # ← DEVE TER ESTA LINHA!
]