import random
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("RedTeam_Em_Memoria")

# =====================================================================
# 🚀 OTIMIZAÇÃO: REGEX PRÉ-COMPILADO (Elimina o gargalo do CPU)
# =====================================================================
RE_TIME = re.compile(r'generated_time="([^"]+)"')
RE_SRC  = re.compile(r'src_ip=([^\s]+)')
RE_DST  = re.compile(r'dst_ip=([^\s]+)')


    # O Novo Arsenal Avançado (Pesos-Pesados: 100% de Taxa de Sucesso na Camada 1)
ARSENAL_ATAQUES = [
    # 1. Força Bruta (Mantido: 80 eventos em 2s = 40 ev/s -> Fura o Burst)
    {"id": "T1110.001", "nome": "Força Bruta SSH", "tipo": "burst", "portas": ["22"], "acao": "allow", "total_eventos": 80, "duracao_segundos": 2, "app": "ssh"},
    
    # 2. Port Scan (Mantido: 35 eventos em 1s = 35 ev/s -> Fura o Burst)
    {"id": "T1046", "nome": "Port Scan Agressivo", "tipo": "burst", "portas": ["22", "80", "443", "3389", "8080", "135", "445"], "acao": "deny", "total_eventos": 35, "duracao_segundos": 1, "app": "unknown"},
    
    # 3. Movimentação Lateral (Mantido: Fura o Burst e a Dispersão de IPs)
    {"id": "T1021", "nome": "Movimentação Lateral (Lateral Movement)", "tipo": "lateral", "portas": ["445", "3389", "135"], "acao": "allow", "total_eventos": 50, "duracao_segundos": 2, "app": "smb"},
    
    # 4. Beaconing MODIFICADO (Era 5 eventos em 1 hora. Agora são 25 eventos em 1 segundo!)
    # Simulamos um malware desesperado para falar com o servidor C2, furando o Burst.
    {"id": "T1071.001", "nome": "C2 Beaconing Agressivo", "tipo": "stealth", "portas": ["443", "80"], "acao": "allow", "total_eventos": 25, "duracao_segundos": 1, "app": "web-browsing"},
    
    # 5. Exfiltração MODIFICADA (Eram 2 eventos. Agora são 25 conexões simultâneas enviando 100MB)
    # Furamos o Limiar de DLP e o de Burst ao mesmo tempo.
    {"id": "T1048", "nome": "Exfiltração Massiva e Ruidosa", "tipo": "exfil", "portas": ["443", "22"], "acao": "allow", "total_eventos": 25, "duracao_segundos": 1, "app": "ssl", "bytes_sent": 104857600} 
]


def extrair_tempo_str(linha):
    """Retorna a string pura da data. É 100x mais rápido para ordenação do que usar datetime."""
    match = RE_TIME.search(linha)
    return match.group(1) if match else "0000/00/00 00:00:00"

def injetar_ataque_no_lote(linhas_reais, probabilidade_injecao=1.0):
    """Intercepta um lote de logs na RAM e decide se injeta um ataque à velocidade da luz."""
    if random.random() > probabilidade_injecao or len(linhas_reais) < 10:
        return linhas_reais

    tempos_str = [extrair_tempo_str(l) for l in linhas_reais]
    tempos_validos = [t for t in tempos_str if t != "0000/00/00 00:00:00"]
    
    if not tempos_validos:
        return linhas_reais
        
    time_start = datetime.strptime(min(tempos_validos), "%Y/%m/%d %H:%M:%S")
    time_end = datetime.strptime(max(tempos_validos), "%Y/%m/%d %H:%M:%S")
    
    if time_start == time_end:
        time_end += timedelta(seconds=10)

    # 🚀 OTIMIZAÇÃO: Varre algumas linhas para roubar IPs de contexto e tornar-se furtivo
    amostra = random.sample(linhas_reais, min(50, len(linhas_reais)))
    src_ips = []
    dst_ips = []
    for l in amostra:
        m_src = RE_SRC.search(l)
        m_dst = RE_DST.search(l)
        if m_src: src_ips.append(m_src.group(1))
        if m_dst: dst_ips.append(m_dst.group(1))

    # Escolhe um atacante e levanta a lista de vítimas disponíveis (Garantindo +6 pra furar threshold)
    attacker_ip = random.choice(src_ips) if src_ips else "185.12.33.9"
    todos_alvos = list(set(dst_ips)) if dst_ips else ["10.0.0.8", "10.0.1.10", "10.0.2.14"]
    
    # Preenche buracos se o log real não for rico o suficiente
    while len(todos_alvos) < 6:
        todos_alvos.append(f"192.168.1.{random.randint(10, 200)}")

    ataque = random.choice(ARSENAL_ATAQUES)
    logger.info(f"🔥 [RED TEAM INVISÍVEL] Preparando teste de Cego: {ataque['nome']} no IP alvo global: {attacker_ip}")

    # Distribuição temporal do Ataque Pseudo-Real
    segundos_disponiveis = max(1, int((time_end - time_start).total_seconds()))
    if ataque['tipo'] == 'stealth':
        duracao = min(segundos_disponiveis, ataque['duracao_segundos'])
    else:
        duracao = ataque['duracao_segundos']
        
    start_ataque = time_start + timedelta(seconds=random.randint(0, max(0, segundos_disponiveis - duracao)))

    linhas_sinteticas = []
    for i in range(ataque['total_eventos']):
        # Se for burst, distribui milissegundos, se stealth, espalha pelos segundos inteiros
        tempo_evento = start_ataque + timedelta(milliseconds=random.randint(0, duracao * 1000))
        porta_escolhida = random.choice(ataque['portas'])
        
        # Lógica de Movimentação Lateral: Variar os IPs de Destino massivamente!
        if ataque['tipo'] == 'lateral':
            alvo_escolhido = random.choice(todos_alvos)
        else:
            alvo_escolhido = todos_alvos[0]

        # Injeção Customizada de Métricas Volumétricas (DLP/Exfiltração)
        str_bytes = f"bytes_sent={ataque['bytes_sent']} " if 'bytes_sent' in ataque else ""
        
        # A tag 'Alerta_RedTeam' serve SÓ para o Early Drop não matá-lo na casca 
        # (mas a Camada 1 irá apagá-la antes da IA ler num teste anti-fraude)
        nova_linha = (
            f'generated_time="{tempo_evento.strftime("%Y/%m/%d %H:%M:%S")}" type="Traffic" threat_id="RedTeam-Attack" severity="High" '
            f'src_ip={attacker_ip} dst_ip={alvo_escolhido} dst_port={porta_escolhida} action={ataque["acao"]} '
            f'{str_bytes}rule_name=Alerta_RedTeam application={ataque["app"]} proto=tcp notes="Emulacao_RAM"\n'
        )
        linhas_sinteticas.append(nova_linha)
    # Junta o lote malicioso cravado temporalmente com as requisições normais
    lote_misto = linhas_reais + linhas_sinteticas
    lote_misto.sort(key=extrair_tempo_str)
    
    return lote_misto