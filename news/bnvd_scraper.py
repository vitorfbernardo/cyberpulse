import requests
from bs4 import BeautifulSoup
from datetime import datetime
import logging
import time

logger = logging.getLogger(__name__)


class BNVDClient:
    """
    Cliente para o Banco Nacional de Vulnerabilidades (BNVD)
    Usa scraping da página de busca + API para listagem
    COM FALLBACK PARA NVD EM CASO DE ERRO 403
    """
    BASE_URL = "https://bnvd.org"
    API_URL = f"{BASE_URL}/api/v1/vulnerabilities"
    SEARCH_URL = f"{BASE_URL}/busca"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        self.session = requests.Session()
        # Headers completos para simular navegador real
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://bnvd.org/',
            'Origin': 'https://bnvd.org',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'max-age=0',
        })
    
    def search_vulnerabilities(self, query="", limit=20):
        """
        Busca vulnerabilidades no BNVD com fallback para NVD
        
        Args:
            query (str): Termo de busca (CVE ID, produto, keyword)
            limit (int): Limite de resultados
            
        Returns:
            list: Lista de dicionários com dados das vulnerabilidades
        """
        try:
            # Delay de 1 segundo antes de fazer requisição
            time.sleep(1)
            
            # Se for um CVE ID específico, usar página de busca
            if query and query.upper().startswith('CVE-'):
                result = self._search_by_cve_web(query)
                if result:
                    return [result]
                else:
                    # Fallback: tentar NVD
                    logger.warning(f"BNVD falhou para {query}, tentando NVD...")
                    nvd_result = self._fallback_nvd(query)
                    if nvd_result:
                        return [nvd_result]
                    # Se NVD também falhar, buscar na API do BNVD
                    return self._search_api(query="", limit=limit)
            else:
                # Buscar na API para listagem geral
                return self._search_api(query=query, limit=limit)
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(f"Erro 403 no BNVD, usando fallback NVD para {query}")
                # Fallback para NVD em caso de 403
                if query and query.upper().startswith('CVE-'):
                    nvd_result = self._fallback_nvd(query)
                    if nvd_result:
                        return [nvd_result]
            logger.error(f"Erro HTTP ao buscar no BNVD: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro ao buscar no BNVD: {e}")
            return []
    
    def get_vulnerability_by_cve(self, cve_id):
        """
        Busca uma vulnerabilidade específica por CVE ID
        """
        return self._search_by_cve_web(cve_id)
    
    def get_latest_vulnerabilities(self, limit=20):
        """
        Busca as vulnerabilidades mais recentes do BNVD via API
        """
        return self._search_api(query="", limit=limit)
    
    def _search_by_cve_web(self, cve_id):
        """
        Busca um CVE específico via scraping da página web
        """
        try:
            # Delay antes da requisição
            time.sleep(1)
            
            cve_id_clean = cve_id.upper().strip()
            
            # Parâmetros para busca
            params = {
                'cve_id': cve_id_clean,
                'vendor': '',
                'severidade': '',
                'ordenar': 'published',
                'ordem': 'desc'
            }
            
            response = self.session.get(self.SEARCH_URL, params=params, timeout=30)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # CORREÇÃO: Procurar por cards com a classe correta
            all_cards = soup.find_all('div', class_='card')
            
            # Procurar o card que contém o CVE ID
            target_card = None
            for card in all_cards:
                card_text = card.get_text()
                if cve_id_clean in card_text:
                    target_card = card
                    break
            
            if target_card:
                return self._process_web_card(target_card, cve_id_clean)
            else:
                # Fallback: extrair do texto
                if cve_id_clean in response.text:
                    return self._extract_from_text(response.text, cve_id_clean)
            
            logger.warning(f"CVE {cve_id_clean} não encontrado no BNVD")
            return None
            
        except Exception as e:
            logger.error(f"Erro ao buscar {cve_id} na web: {e}")
            return None
    
    def _process_web_card(self, card, cve_id):
        """
        Processa um card de vulnerabilidade da página web do BNVD
        """
        try:
            # Extrair CVE ID do título
            title_elem = card.find('h5', class_='card-title')
            if title_elem:
                link_elem = title_elem.find('a')
                if link_elem:
                    cve_id = link_elem.get_text(strip=True)
            
            # Extrair severidade
            severity = 'N/A'
            severity_badge = card.find('span', class_='badge')
            if severity_badge:
                severity_text = severity_badge.get_text(strip=True).upper()
                # Mapear severidade
                if 'CRÍT' in severity_text or 'CRITICAL' in severity_text:
                    severity = 'CRÍTICO'
                elif 'ALT' in severity_text or 'HIGH' in severity_text or 'ALTA' in severity_text:
                    severity = 'ALTO'
                elif 'MÉD' in severity_text or 'MEDIUM' in severity_text or 'MÉDIA' in severity_text:
                    severity = 'MÉDIO'
                elif 'BAI' in severity_text or 'LOW' in severity_text or 'BAIXA' in severity_text:
                    severity = 'BAIXO'
            
            # Extrair descrição COMPLETA da página de detalhes
            description = ''
            detail_link = f"{self.BASE_URL}/vulnerabilidade/{cve_id}"
            
            try:
                detail_response = self.session.get(detail_link, timeout=30)
                
                if detail_response.status_code == 200:
                    detail_soup = BeautifulSoup(detail_response.content, 'html.parser')
                    
                    # Tentar encontrar a descrição completa em vários locais possíveis
                    desc_full = detail_soup.find('p', class_='card-text')
                    
                    if not desc_full or len(desc_full.get_text(strip=True)) < 100:
                        desc_full = detail_soup.find('div', class_='vulnerability-description')
                    
                    if not desc_full or len(desc_full.get_text(strip=True)) < 100:
                        main_card = detail_soup.find('div', class_='card-body')
                        if main_card:
                            paragraphs = main_card.find_all('p')
                            if paragraphs:
                                description = ' '.join([p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)])
                    
                    if desc_full and not description:
                        description = desc_full.get_text(strip=True)
                    
            except Exception as e:
                logger.error(f"Erro ao buscar página de detalhes: {e}")
            
            # Fallback: usar descrição do card se não conseguiu da página de detalhes
            if not description or len(description) < 50:
                desc_elem = card.find('p', class_='card-text')
                if desc_elem:
                    description = desc_elem.get_text(strip=True)
        
            # Extrair CVSS Score
            cvss_score = 'N/A'
            score_elem = card.find('span', class_=lambda x: x and 'h4' in x and 'text-primary' in x)
            
            if score_elem:
                score_text = score_elem.get_text(strip=True)
                try:
                    import re
                    score_match = re.search(r'(\d+\.?\d*)', score_text)
                    if score_match:
                        cvss_score = float(score_match.group(1))
                except Exception as e:
                    logger.error(f"Erro ao processar score: {e}")
                    cvss_score = 'N/A'
            else:
                score_elem_alt = card.select_one('span.h4.text-primary')
                if score_elem_alt:
                    score_text = score_elem_alt.get_text(strip=True)
                    try:
                        import re
                        score_match = re.search(r'(\d+\.?\d*)', score_text)
                        if score_match:
                            cvss_score = float(score_match.group(1))
                    except:
                        cvss_score = 'N/A'
            
            # Extrair datas
            pub_date = datetime.now().strftime('%Y-%m-%d')
            date_div = card.find('div', class_='text-muted')
            if date_div:
                date_text = date_div.get_text()
                import re
                date_match = re.search(r'(\d{2}/\d{2}/\d{4})', date_text)
                if date_match:
                    date_str = date_match.group(1)
                    try:
                        parts = date_str.split('/')
                        pub_date = f"{parts[2]}-{parts[1]}-{parts[0]}"
                    except:
                        pass
            
            # Extrair CWE (se houver)
            cwe_badges = card.find_all('span', class_='badge bg-light')
            cwe_list = [badge.get_text(strip=True) for badge in cwe_badges] if cwe_badges else []
            
            # Link para detalhes
            link = f"{self.BASE_URL}/vulnerabilidade/{cve_id}"
            
            return {
                'cve_id': cve_id,
                'title': f"{cve_id} - {severity}",
                'description': description if description else f"Vulnerabilidade {cve_id} catalogada no BNVD",
                'severity': severity,
                'cvss_score': cvss_score,
                'cwe': ', '.join(cwe_list[:3]) if cwe_list else 'N/A',
                'link': link,
                'source': '🇧🇷 BNVD',
                'published_date': pub_date,
                'category': 'vulnerability',
                'has_portuguese': True,
            }
            
        except Exception as e:
            logger.error(f"Erro ao processar card: {e}")
            return None
    
    def _extract_from_text(self, html_text, cve_id):
        """
        Extrai informações básicas do HTML quando estrutura não é clara
        """
        try:
            # Procurar por padrões no texto
            description = ''
            
            # Tentar encontrar descrição perto do CVE ID
            soup = BeautifulSoup(html_text, 'html.parser')
            
            # Procurar texto que contenha o CVE
            for elem in soup.find_all(text=lambda t: cve_id in str(t).upper() if t else False):
                # Pegar elementos próximos
                parent = elem.find_parent(['div', 'article', 'section'])
                if parent:
                    # Pegar todo o texto do parent
                    full_text = parent.get_text(strip=True)
                    # Limitar a 500 caracteres
                    description = full_text[:500]
                    break
            
            # Determinar severidade do texto
            severity = 'MÉDIO'  # Default
            text_upper = html_text.upper()
            if 'CRÍTICO' in text_upper or 'CRITICAL' in text_upper:
                severity = 'CRÍTICO'
            elif 'ALTO' in text_upper or 'HIGH' in text_upper:
                severity = 'ALTO'
            elif 'BAIXO' in text_upper or 'LOW' in text_upper:
                severity = 'BAIXO'
            
            return {
                'cve_id': cve_id,
                'title': f"{cve_id} - {severity}",
                'description': description if description else f"Vulnerabilidade {cve_id} encontrada no BNVD",
                'severity': severity,
                'cvss_score': 'N/A',
                'link': f"{self.BASE_URL}/vulnerability/{cve_id}",
                'source': '🇧🇷 BNVD',
                'published_date': datetime.now().strftime('%Y-%m-%d'),
                'category': 'vulnerability',
                'has_portuguese': True,
            }
            
        except Exception as e:
            logger.error(f"Erro ao extrair do texto: {e}")
            return None
    
    def _search_api(self, query="", limit=20):
        """
        Busca vulnerabilidades via API (para listagem geral)
        """
        try:
            # Delay antes da requisição
            time.sleep(1)
            
            params = {'limit': min(limit, 100)}
            
            response = self.session.get(self.API_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vuln_list = data.get('data', [])
            
            results = []
            for vuln in vuln_list[:limit]:
                processed = self._process_api_vulnerability(vuln)
                if processed:
                    results.append(processed)
            
            return results
            
        except Exception as e:
            logger.error(f"Erro ao buscar na API: {e}")
            return []
    
    def _process_api_vulnerability(self, vuln):
        """
        Processa vulnerabilidade da API
        """
        try:
            cve_id = vuln.get('cve_id', 'N/A')
            
            # Descrição em português
            description = ''
            descriptions_pt = vuln.get('descriptions_pt', [])
            
            if descriptions_pt:
                for desc in descriptions_pt:
                    if isinstance(desc, dict):
                        description = desc.get('value', '')
                        if description:
                            break
            
            # Fallback para inglês
            if not description:
                descriptions = vuln.get('descriptions', [])
                for desc in descriptions:
                    if isinstance(desc, dict):
                        description = desc.get('value', '')
                        if description:
                            break
            
            # CVSS
            cvss_metrics = vuln.get('cvss_metrics', {})
            cvss_score = 0
            severity = 'N/A'
            
            if 'cvssMetricV31' in cvss_metrics and cvss_metrics['cvssMetricV31']:
                cvss_data = cvss_metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'N/A')
            
            severity_pt = {
                'LOW': 'BAIXO',
                'MEDIUM': 'MÉDIO',
                'HIGH': 'ALTO',
                'CRITICAL': 'CRÍTICO'
            }.get(severity.upper(), severity)
            
            # Data
            pub_date = vuln.get('published_date', vuln.get('created_at', ''))
            if pub_date:
                try:
                    pub_date_obj = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    pub_date = pub_date_obj.strftime('%Y-%m-%d')
                except:
                    pub_date = str(pub_date)[:10]
            else:
                pub_date = datetime.now().strftime('%Y-%m-%d')
            
            return {
                'cve_id': cve_id,
                'title': f"{cve_id} - {severity_pt}",
                'description': description[:500] if description else f"Vulnerabilidade {cve_id} (BNVD)",
                'severity': severity_pt,
                'cvss_score': cvss_score,
                'link': f"{self.BASE_URL}/vulnerability/{cve_id}",
                'source': '🇧🇷 BNVD',
                'published_date': pub_date,
                'category': 'vulnerability',
                'has_portuguese': bool(descriptions_pt),
            }
            
        except Exception as e:
            logger.error(f"Erro ao processar API: {e}")
            return None
    
    def _fallback_nvd(self, cve_id):
        """
        NOVO: Busca no NVD (National Vulnerability Database) como fallback
        quando BNVD está inacessível (erro 403 ou outros)
        """
        try:
            logger.info(f"Buscando {cve_id} no NVD (fallback)...")
            
            # Delay antes da requisição
            time.sleep(1)
            
            cve_id_clean = cve_id.upper().strip()
            
            params = {'cveId': cve_id_clean}
            
            # Headers específicos para NVD
            nvd_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
            }
            
            response = requests.get(
                self.NVD_API_URL,
                params=params,
                headers=nvd_headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Verificar se encontrou vulnerabilidades
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                logger.warning(f"CVE {cve_id_clean} não encontrado no NVD")
                return None
            
            # Pegar primeira vulnerabilidade
            vuln_data = vulnerabilities[0].get('cve', {})
            
            # Extrair descrição (inglês)
            description = ''
            descriptions = vuln_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extrair CVSS Score e Severidade
            cvss_score = 'N/A'
            severity = 'N/A'
            
            metrics = vuln_data.get('metrics', {})
            
            # Tentar CVSS v3.1 primeiro
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'N/A')
            # Fallback para CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'N/A')
            # Fallback para CVSS v2.0
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'N/A')
            
            # Traduzir severidade pra português
            severity_pt = {
                'LOW': 'BAIXO',
                'MEDIUM': 'MÉDIO',
                'HIGH': 'ALTO',
                'CRITICAL': 'CRÍTICO'
            }.get(str(severity).upper(), severity)
            
            # Extrair data de publicação
            pub_date = vuln_data.get('published', '')
            if pub_date:
                try:
                    pub_date_obj = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    pub_date = pub_date_obj.strftime('%Y-%m-%d')
                except:
                    pub_date = str(pub_date)[:10]
            else:
                pub_date = datetime.now().strftime('%Y-%m-%d')
            
            # Extrair CWE
            weaknesses = vuln_data.get('weaknesses', [])
            cwe_list = []
            for weakness in weaknesses:
                descriptions = weakness.get('description', [])
                for desc in descriptions:
                    cwe_value = desc.get('value', '')
                    if cwe_value.startswith('CWE-'):
                        cwe_list.append(cwe_value)
            
            return {
                'cve_id': cve_id_clean,
                'title': f"{cve_id_clean} - {severity_pt}",
                'description': description if description else f"Vulnerabilidade {cve_id_clean} (NVD)",
                'severity': severity_pt,
                'cvss_score': cvss_score,
                'cwe': ', '.join(cwe_list[:3]) if cwe_list else 'N/A',
                'link': f"https://nvd.nist.gov/vuln/detail/{cve_id_clean}",
                'source': '🇺🇸 NVD',  # Indicador de que veio do fallback
                'published_date': pub_date,
                'category': 'vulnerability',
                'has_portuguese': False,  # NVD é em inglês
            }
            
        except Exception as e:
            logger.error(f"Erro ao buscar {cve_id} no NVD (fallback): {e}")
            return None


# Instância global
bnvd_client = BNVDClient()