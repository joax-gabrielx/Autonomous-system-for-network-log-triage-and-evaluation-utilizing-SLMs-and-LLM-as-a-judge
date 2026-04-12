import os
import requests
import logging
from dotenv import load_dotenv

# Carrega a chave do arquivo .env
load_dotenv()
logger = logging.getLogger("MCP_AbuseIPDB")

class MCPThreatIntel:
    """
    Servidor MCP (Model Context Protocol) para enriquecimento de Threat Intelligence.
    Conecta a arquitetura local com a base global do AbuseIPDB.
    """
    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def consultar_ip(self, ip_alvo):
        """Busca a ficha criminal de um IP nos últimos 90 dias."""
        if not self.api_key:
            logger.error("API Key do AbuseIPDB não encontrada no arquivo .env!")
            return "[MCP Threat Intel] Falha: API Key ausente."

        querystring = {
            'ipAddress': ip_alvo,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        try:
            logger.info(f"🌍 [MCP] Consultando AbuseIPDB para o alvo: {ip_alvo}...")
            resposta = requests.get(self.base_url, headers=headers, params=querystring, timeout=5)
            
            if resposta.status_code == 200:
                dados = resposta.json()['data']
                score = dados.get('abuseConfidenceScore', 0)
                reports = dados.get('totalReports', 0)
                pais = dados.get('countryCode', 'Desconhecido')
                
                # Regra de formatação para a IA (Tradução do JSON da API para texto legível)
                if score > 0:
                    return f"[🌍 THREAT INTEL: ALERTA GLOBAL] O IP tem um Score de Abuso de {score}%. Foi reportado {reports} vezes no mundo nos últimos 90 dias. Origem: {pais}."
                else:
                    return f"[🌍 THREAT INTEL: LIMPO] O IP tem Score 0%. Nenhum reporte global recente. Origem: {pais}."
            
            else:
                return f"[MCP Threat Intel] Erro na API: HTTP {resposta.status_code}"
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Falha de conexão com AbuseIPDB: {e}")
            return "[MCP Threat Intel] Timeout ou erro de rede ao consultar a API."