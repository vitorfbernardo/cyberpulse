// Efeitos interativos para o login cyber
document.addEventListener('DOMContentLoaded', function() {
    // Efeito nos inputs
    const inputs = document.querySelectorAll('.cyber-input');
    
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            if (this.value === '') {
                this.parentElement.classList.remove('focused');
            }
        });
        
        // Efeito de digitação
        input.addEventListener('input', function() {
            if (this.value.length > 0) {
                this.parentElement.classList.add('has-value');
            } else {
                this.parentElement.classList.remove('has-value');
            }
        });
    });
    
    // Efeito no botão
    const button = document.querySelector('.cyber-btn');
    
    button.addEventListener('mouseenter', function() {
        const glow = this.querySelector('.btn-glow');
        glow.style.transition = 'none';
        glow.style.transform = 'rotate(45deg)';
        
        setTimeout(() => {
            glow.style.transition = 'transform 0.5s ease';
            glow.style.transform = 'rotate(0deg)';
        }, 10);
    });
    
    // Efeito de partículas no clique
    button.addEventListener('click', function(e) {
        createParticles(e.clientX, e.clientY);
    });
    
    // Criar partículas
    function createParticles(x, y) {
        for (let i = 0; i < 8; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = x + 'px';
            particle.style.top = y + 'px';
            particle.style.backgroundColor = getRandomColor();
            
            document.body.appendChild(particle);
            
            // Animação
            const angle = Math.random() * Math.PI * 2;
            const speed = 2 + Math.random() * 3;
            const vx = Math.cos(angle) * speed;
            const vy = Math.sin(angle) * speed;
            
            let posX = x;
            let posY = y;
            
            function animate() {
                posX += vx;
                posY += vy;
                
                particle.style.left = posX + 'px';
                particle.style.top = posY + 'px';
                particle.style.opacity = parseFloat(particle.style.opacity || 1) - 0.02;
                
                if (parseFloat(particle.style.opacity) > 0) {
                    requestAnimationFrame(animate);
                } else {
                    particle.remove();
                }
            }
            
            requestAnimationFrame(animate);
        }
    }
    
    function getRandomColor() {
        const colors = ['#00ff88', '#00ccff', '#ff00ff', '#ffff00'];
        return colors[Math.floor(Math.random() * colors.length)];
    }
    
    // Efeito de digitação no título
    const title = document.querySelector('.cyber-title');
    const originalText = title.textContent;
    
    function glitchText() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let glitched = '';
        
        for (let i = 0; i < originalText.length; i++) {
            if (Math.random() > 0.9) {
                glitched += chars[Math.floor(Math.random() * chars.length)];
            } else {
                glitched += originalText[i];
            }
        }
        
        title.textContent = glitched;
        
        setTimeout(() => {
            title.textContent = originalText;
        }, 100);
    }
    
    // Glitch aleatório
    setInterval(() => {
        if (Math.random() > 0.7) {
            glitchText();
        }
    }, 3000);
    
    // Efeito de scanline no status
    const statusDots = document.querySelectorAll('.status-dot.active');
    
    setInterval(() => {
        statusDots.forEach(dot => {
            dot.style.boxShadow = `0 0 ${10 + Math.random() * 10}px #00ff88`;
        });
    }, 500);
});