import requests
import logging
from datetime import datetime
from django.conf import settings
import hashlib

logger = logging.getLogger(__name__)


class ThreatIntelClient:
    """
    Cliente integrado para múltiplas fontes de Threat Intelligence
    - AbuseIPDB (reputação de IPs)
    - AlienVault OTX (hashes, IPs, domains)
    - IPGeolocation (geolocalização)
    - VirusTotal (análise completa)
    """
    
    def __init__(self):
        # API Keys (via environment variables)
        self.abuseipdb_key = getattr(settings, 'ABUSEIPDB_API_KEY', '')
        self.otx_key = getattr(settings, 'OTX_API_KEY', '')
        self.ipgeo_key = getattr(settings, 'IPGEOLOCATION_API_KEY', '')
        self.virustotal_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberPulse-ThreatIntel/1.0'
        })
    
    def analyze_ip(self, ip_address):
        """
        Análise completa de um endereço IP
        """
        result = {
            'ip': ip_address,
            'type': 'ip',
            'timestamp': datetime.now().isoformat(),
            'geolocation': {},
            'reputation': {},
            'threat_intel': {},
            'recommendations': []
        }
        
        # 1. Geolocalização
        geo_data = self._get_ip_geolocation(ip_address)
        if geo_data:
            result['geolocation'] = geo_data
        
        # 2. Reputação (AbuseIPDB)
        abuse_data = self._check_abuseipdb(ip_address)
        if abuse_data:
            result['reputation'] = abuse_data
        
        # 3. Threat Intelligence (OTX)
        otx_data = self._check_otx_ip(ip_address)
        if otx_data:
            result['threat_intel']['otx'] = otx_data
        
        # 4. VirusTotal
        vt_data = self._check_virustotal_ip(ip_address)
        if vt_data:
            result['threat_intel']['virustotal'] = vt_data
        
        # 5. Gerar recomendações
        result['recommendations'] = self._generate_recommendations(result)
        
        return result
    
    def analyze_hash(self, hash_value):
        """
        Análise completa de um hash (MD5/SHA256)
        """
        result = {
            'hash': hash_value,
            'type': 'hash',
            'hash_type': self._detect_hash_type(hash_value),
            'timestamp': datetime.now().isoformat(),
            'threat_intel': {},
            'malware_families': [],
            'recommendations': []
        }
        
        # 1. Abuse.ch (MalwareBazaar)
        abuse_data = self._check_malwarebazaar(hash_value)
        if abuse_data:
            result['threat_intel']['abuse_ch'] = abuse_data
        
        # 2. AlienVault OTX
        otx_data = self._check_otx_hash(hash_value)
        if otx_data:
            result['threat_intel']['otx'] = otx_data
        
        # 3. VirusTotal
        vt_data = self._check_virustotal_hash(hash_value)
        if vt_data:
            result['threat_intel']['virustotal'] = vt_data
        
        # 4. Extrair famílias de malware
        result['malware_families'] = self._extract_malware_families(result)
        
        # 5. Gerar recomendações
        result['recommendations'] = self._generate_recommendations(result)
        
        return result
    
    def analyze_domain(self, domain):
        """
        Análise completa de um domínio
        """
        result = {
            'domain': domain,
            'type': 'domain',
            'timestamp': datetime.now().isoformat(),
            'threat_intel': {},
            'recommendations': []
        }
        
        # 1. AlienVault OTX
        otx_data = self._check_otx_domain(domain)
        if otx_data:
            result['threat_intel']['otx'] = otx_data
        
        # 2. VirusTotal
        vt_data = self._check_virustotal_domain(domain)
        if vt_data:
            result['threat_intel']['virustotal'] = vt_data
        
        # 3. Gerar recomendações
        result['recommendations'] = self._generate_recommendations(result)
        
        return result
    
    # ==================== IP GEOLOCATION ====================
    
    def _get_ip_geolocation(self, ip):
        """
        Geolocalização via ipgeolocation.io (1.000 requests/dia grátis)
        """
        try:
            if not self.ipgeo_key:
                # Fallback: ip-api.com (sem key, 45 req/min)
                url = f"http://ip-api.com/json/{ip}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                    }
            else:
                # Com API key
                url = f"https://api.ipgeolocation.io/ipgeo"
                params = {'apiKey': self.ipgeo_key, 'ip': ip}
                response = self.session.get(url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'country': data.get('country_name', 'N/A'),
                        'country_code': data.get('country_code2', 'N/A'),
                        'region': data.get('state_prov', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('organization', 'N/A'),
                        'lat': data.get('latitude', 0),
                        'lon': data.get('longitude', 0),
                    }
        except Exception as e:
            logger.error(f"Erro ao buscar geolocalização: {e}")
        
        return {}
    
    # ==================== ABUSEIPDB ====================
    
    def _check_abuseipdb(self, ip):
        """
        Verifica reputação no AbuseIPDB (1.000 requests/dia grátis)
        """
        try:
            if not self.abuseipdb_key:
                logger.warning("AbuseIPDB API key não configurada")
                return None
            
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                
                # Determinar nível de risco
                if abuse_score >= 80:
                    risk_level = 'ALTO'
                    risk_color = '🔴'
                elif abuse_score >= 50:
                    risk_level = 'MÉDIO'
                    risk_color = '🟡'
                elif abuse_score > 0:
                    risk_level = 'BAIXO'
                    risk_color = '🟢'
                else:
                    risk_level = 'LIMPO'
                    risk_color = '🟢'
                
                return {
                    'score': abuse_score,
                    'risk_level': risk_level,
                    'risk_color': risk_color,
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported': data.get('lastReportedAt', 'N/A'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode', 'N/A'),
                    'usage_type': data.get('usageType', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'domain': data.get('domain', 'N/A'),
                }
        except Exception as e:
            logger.error(f"Erro ao consultar AbuseIPDB: {e}")
        
        return None
    
    # ==================== ALIENVAULT OTX ====================
    
    def _check_otx_ip(self, ip):
        """
        Verifica IP no AlienVault OTX
        """
        try:
            if not self.otx_key:
                logger.warning("OTX API key não configurada")
                return None
            
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Buscar pulses relacionados
                pulses_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware"
                pulses_response = self.session.get(pulses_url, headers=headers, timeout=10)
                
                pulses = []
                if pulses_response.status_code == 200:
                    pulses_data = pulses_response.json()
                    pulses = pulses_data.get('data', [])[:5]  # Top 5
                
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': [p.get('hash', 'N/A') for p in pulses],
                    'found': data.get('pulse_info', {}).get('count', 0) > 0,
                }
        except Exception as e:
            logger.error(f"Erro ao consultar OTX (IP): {e}")
        
        return None
    
    def _check_otx_hash(self, hash_value):
        """
        Verifica hash no AlienVault OTX
        """
        try:
            if not self.otx_key:
                logger.warning("OTX API key não configurada")
                return None
            
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                return {
                    'pulse_count': pulse_info.get('count', 0),
                    'found': pulse_info.get('count', 0) > 0,
                    'pulses': [p.get('name', 'N/A') for p in pulse_info.get('pulses', [])[:5]]
                }
        except Exception as e:
            logger.error(f"Erro ao consultar OTX (hash): {e}")
        
        return None
    
    def _check_otx_domain(self, domain):
        """
        Verifica domínio no AlienVault OTX
        """
        try:
            if not self.otx_key:
                logger.warning("OTX API key não configurada")
                return None
            
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                return {
                    'pulse_count': pulse_info.get('count', 0),
                    'found': pulse_info.get('count', 0) > 0,
                    'pulses': [p.get('name', 'N/A') for p in pulse_info.get('pulses', [])[:5]]
                }
        except Exception as e:
            logger.error(f"Erro ao consultar OTX (domain): {e}")
        
        return None
    
    # ==================== MALWAREBAZAAR (ABUSE.CH) ====================
    
    def _check_malwarebazaar(self, hash_value):
        """
        Verifica hash no MalwareBazaar (Abuse.ch)
        API pública, sem necessidade de key
        """
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            
            data = {
                'query': 'get_info',
                'hash': hash_value
            }
            
            response = self.session.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    malware_data = result.get('data', [{}])[0]
                    
                    return {
                        'found': True,
                        'signature': malware_data.get('signature', 'N/A'),
                        'file_type': malware_data.get('file_type', 'N/A'),
                        'file_size': malware_data.get('file_size', 0),
                        'first_seen': malware_data.get('first_seen', 'N/A'),
                        'last_seen': malware_data.get('last_seen', 'N/A'),
                        'file_name': malware_data.get('file_name', 'N/A'),
                        'reporter': malware_data.get('reporter', 'N/A'),
                    }
                else:
                    return {'found': False}
        except Exception as e:
            logger.error(f"Erro ao consultar MalwareBazaar: {e}")
        
        return None
    
    # ==================== VIRUSTOTAL ====================
    
    def _check_virustotal_ip(self, ip):
        """
        Verifica IP no VirusTotal
        """
        try:
            if not self.virustotal_key:
                logger.warning("VirusTotal API key não configurada")
                return None
            
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                
                return {
                    'malicious': malicious,
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': total,
                    'detection_rate': f"{malicious}/{total}" if total > 0 else "0/0",
                    'reputation': attributes.get('reputation', 0),
                }
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal (IP): {e}")
        
        return None
    
    def _check_virustotal_hash(self, hash_value):
        """
        Verifica hash no VirusTotal
        """
        try:
            if not self.virustotal_key:
                logger.warning("VirusTotal API key não configurada")
                return None
            
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                
                return {
                    'malicious': malicious,
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': total,
                    'detection_rate': f"{malicious}/{total}" if total > 0 else "0/0",
                    'file_type': attributes.get('type_description', 'N/A'),
                    'size': attributes.get('size', 0),
                    'names': attributes.get('names', [])[:3],
                }
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal (hash): {e}")
        
        return None
    
    def _check_virustotal_domain(self, domain):
        """
        Verifica domínio no VirusTotal
        """
        try:
            if not self.virustotal_key:
                logger.warning("VirusTotal API key não configurada")
                return None
            
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                
                return {
                    'malicious': malicious,
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': total,
                    'detection_rate': f"{malicious}/{total}" if total > 0 else "0/0",
                    'reputation': attributes.get('reputation', 0),
                }
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal (domain): {e}")
        
        return None
    
    # ==================== HELPERS ====================
    
    def _detect_hash_type(self, hash_value):
        """
        Detecta tipo de hash pelo tamanho
        """
        hash_len = len(hash_value)
        
        if hash_len == 32:
            return 'MD5'
        elif hash_len == 40:
            return 'SHA1'
        elif hash_len == 64:
            return 'SHA256'
        else:
            return 'UNKNOWN'
    
    def _extract_malware_families(self, result):
        """
        Extrai famílias de malware de todas as fontes
        """
        families = set()
        
        # Abuse.ch
        abuse_ch = result.get('threat_intel', {}).get('abuse_ch', {})
        if abuse_ch and abuse_ch.get('found'):
            signature = abuse_ch.get('signature', '')
            if signature and signature != 'N/A':
                families.add(signature)
        
        # OTX pulses
        otx = result.get('threat_intel', {}).get('otx', {})
        if otx and otx.get('found'):
            for pulse in otx.get('pulses', []):
                if pulse != 'N/A':
                    families.add(pulse)
        
        return list(families)[:5]  # Top 5
    
    def _generate_recommendations(self, result):
        """
        Gera recomendações baseadas na análise
        """
        recommendations = []
        result_type = result.get('type')
        
        if result_type == 'ip':
            reputation = result.get('reputation', {})
            score = reputation.get('score', 0)
            
            if score >= 80:
                recommendations.append({
                    'level': 'critical',
                    'icon': '🔴',
                    'title': 'BLOQUEAR IMEDIATAMENTE',
                    'actions': [
                        'Adicionar ao firewall/WAF',
                        'Verificar logs por conexões deste IP',
                        'Investigar possível compromisso de sistemas',
                        'Reportar ao SOC/CSIRT'
                    ]
                })
            elif score >= 50:
                recommendations.append({
                    'level': 'warning',
                    'icon': '🟡',
                    'title': 'MONITORAR COM ATENÇÃO',
                    'actions': [
                        'Adicionar à watchlist do SIEM',
                        'Revisar logs de acesso',
                        'Considerar bloqueio temporário'
                    ]
                })
            else:
                recommendations.append({
                    'level': 'info',
                    'icon': '🟢',
                    'title': 'IP APARENTEMENTE LIMPO',
                    'actions': [
                        'Manter monitoramento padrão',
                        'Documentar consulta para auditoria'
                    ]
                })
        
        elif result_type == 'hash':
            threat_intel = result.get('threat_intel', {})
            
            # Se foi encontrado em qualquer fonte
            if any(source.get('found') for source in threat_intel.values() if source):
                recommendations.append({
                    'level': 'critical',
                    'icon': '🔴',
                    'title': 'MALWARE CONFIRMADO',
                    'actions': [
                        'Isolar sistemas afetados IMEDIATAMENTE',
                        'Executar scan completo de antivírus',
                        'Verificar logs de execução',
                        'Reportar ao SOC/CSIRT',
                        'Preservar evidências para análise forense'
                    ]
                })
            else:
                recommendations.append({
                    'level': 'info',
                    'icon': '🟢',
                    'title': 'HASH NÃO ENCONTRADO EM BASES DE MALWARE',
                    'actions': [
                        'Considerar análise em sandbox',
                        'Enviar amostra para VirusTotal se suspeito',
                        'Documentar para referência futura'
                    ]
                })
        
        elif result_type == 'domain':
            threat_intel = result.get('threat_intel', {})
            vt = threat_intel.get('virustotal', {})
            
            if vt and vt.get('malicious', 0) > 0:
                recommendations.append({
                    'level': 'critical',
                    'icon': '🔴',
                    'title': 'DOMÍNIO MALICIOSO DETECTADO',
                    'actions': [
                        'Bloquear no DNS/Proxy',
                        'Verificar logs de acesso ao domínio',
                        'Investigar sistemas que acessaram',
                        'Adicionar à blacklist'
                    ]
                })
            else:
                recommendations.append({
                    'level': 'info',
                    'icon': '🟢',
                    'title': 'DOMÍNIO APARENTEMENTE LIMPO',
                    'actions': [
                        'Manter monitoramento padrão',
                        'Documentar consulta'
                    ]
                })
        
        return recommendations
    

# Instância global
threat_intel_client = ThreatIntelClient()