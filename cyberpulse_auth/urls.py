from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from news.views import home, monitoramento, alertas, relatorios, configuracoes, busca, threat_intel_view

urlpatterns = [
    # Página inicial
    path('', home, name='home'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # Login personalizado (URL SIMPLIFICADA!)
    path('login/',
         auth_views.LoginView.as_view(
             template_name='registration/login.html',
             redirect_authenticated_user=True
         ), 
         name='login'),
    
    # Logout
    path('logout/',
         auth_views.LogoutView.as_view(), 
         name='logout'),
    
    # Páginas do sistema
    path('monitoramento/', monitoramento, name='monitoramento'),
    path('alertas/', alertas, name='alertas'),
    path('relatorios/', relatorios, name='relatorios'),
    path('configuracoes/', configuracoes, name='configuracoes'),
    path('busca/', busca, name='busca'),
    path('threat-intel/', threat_intel_view, name='threat_intel'),
]