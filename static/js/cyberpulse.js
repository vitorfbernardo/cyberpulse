// JavaScript do CyberPulse
document.addEventListener('DOMContentLoaded', function() {
    // Efeito no botão de notificações
    const notifBtn = document.querySelector('.notif-btn');
    if (notifBtn) {
        notifBtn.addEventListener('click', function() {
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = 'scale(1)';
            }, 150);
            
            // Simular leitura de notificações
            const notifCount = this.querySelector('.notif-count');
            if (notifCount && notifCount.textContent !== '0') {
                notifCount.textContent = '0';
                notifCount.style.opacity = '0.5';
            }
        });
    }
    
    // Efeito nos links de navegação
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        link.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
    
    // Atualizar status em tempo real
    function updateStatus() {
        const statusDots = document.querySelectorAll('.status-dot.active');
        statusDots.forEach(dot => {
            const randomIntensity = 5 + Math.random() * 3;
            dot.style.boxShadow = `0 0 ${randomIntensity}px var(--cyber-green)`;
        });
    }
    
    // Atualizar status a cada 5 segundos
    setInterval(updateStatus, 5000);
});