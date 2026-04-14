import os
import json
import logging
import time
import requests
import hashlib
import re
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from typing import List
from core.mcp_threat_intel import MCPThreatIntel
from config import ARQUIVO_PLAYBOOK, ARQUIVO_SFT, ARQUIVO_METRICAS, SLM_MODELO, OLLAMA_URL, OLLAMA_KEEP_ALIVE, ARQUIVO_BLACKLIST

load_dotenv()
logging.basicConfig(level=logging.INFO, format='[Camada3_Agente] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("AgenteSOC")

# =====================================================================
# 1. MODELOS DE DADOS E SCHEMA RÍGIDO (STRUCTURED OUTPUTS)
# =====================================================================
class Incidente(BaseModel):
    id_alvo: str = Field(..., description="O IP de origem do atacante.")
    padrao_ataque: str = Field(..., description="Os dados extraídos do firewall.")
    dica_rag: str = Field(..., description="A regra da base de conhecimento.")
    
    # Valores default atuam como última linha de defesa, mas o Schema do Ollama fará o trabalho pesado
    analise_contexto: str = Field(default="Análise omitida.", description="PASSO 1: Pense em voz alta. Analise o tempo e o espaço da ameaça.")
    justificativa: str = Field(default="Justificativa omitida.", description="PASSO 2: Crie uma justificativa técnica curta baseada na análise.")
    veredito: str = Field(default="MONITORAR", description="PASSO 3: Apenas 'BLOQUEAR', 'FALSO_POSITIVO' ou 'MONITORAR'.")
    nivel_confianca: str = Field(default="BAIXA", description="PASSO 4: Apenas 'ALTA', 'MEDIA' ou 'BAIXA'.")

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

class BatchIA(BaseModel):
    avaliacoes: List[Incidente]

# =====================================================================
# 2. MOTOR DO AGENTE SOC
# =====================================================================
class Camada3AgenteSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK = str(ARQUIVO_PLAYBOOK)
        self.ARQUIVO_SFT = str(ARQUIVO_SFT)
        self.ARQUIVO_METRICAS = str(ARQUIVO_METRICAS)
        self.ARQUIVO_BLACKLIST = str(ARQUIVO_BLACKLIST)
        
        self.MODELO = SLM_MODELO 
        self.OLLAMA_URL = OLLAMA_URL
        self.OLLAMA_KEEP_ALIVE = OLLAMA_KEEP_ALIVE
        self.cache_decisoes = {}
        self.mcp_intel = MCPThreatIntel() 

    def _consultar_ia_batch(self, lista_incidentes):
        prompt_sistema = """Você é o Aegis, um Analista SOC Nível 3.
Sua tarefa é avaliar incidentes de rede e gerar a cadeia de pensamento completa OBRIGATORIAMENTE, sem deixar campos vazios.

[REGRAS DE NEGÓCIO ESTRITAS - LEIA COM ATENÇÃO]
1. ANTI-ALUCINAÇÃO (CRÍTICO): NUNCA invente dados. NUNCA copie os valores numéricos, IPs ou portas dos "Exemplos" abaixo. Você deve analisar EXCLUSIVAMENTE os dados reais presentes no campo 'padrao_ataque' do lote atual. 
2. O PESO DO FIREWALL: Se o log contiver 'FW-SEVERIDADE: HIGH' ou 'CRITICAL', isso é prova incontestável de ataque. Cite isso obrigatoriamente.
3. INTELIGÊNCIA GLOBAL E ZERO-DAY: Se a tag '[🌍 THREAT INTEL]' mostrar um score alto, confirme o bloqueio. Se mostrar score BAIXO (ex: 0% ou 1%) MAS o firewall físico mostrar anomalias graves (Burst Alto, Severidade High, Movimentação Lateral), justifique explicitamente que se trata de um ataque direcionado ou infraestrutura nova (Zero-Day).
4. CONCORDÂNCIA E OVERRIDE: Só discorde do RAG se ele disser "Falso Positivo" mas os dados físicos apontarem anomalias graves.

[ESTRUTURA OBRIGATÓRIA DA ANALISE DE CONTEXTO]
Para evitar análises rasas, o seu campo "analise_contexto" DEVE conter exatamente estes 3 passos lógicos. Você será sumariamente punido se omitir tags presentes no log.
- Fatos Internos: Liste EXPLICITAMENTE e copie os termos literais encontrados para: Comportamento Temporal (ex: [BURST AGUDO]), Dispersão Espacial (ex: [FOCADO]), FW-SEVERIDADE, FW-THREAT e a volumetria exata de eventos. Em seguida, descreva o ataque.
- Fatos Externos: Qual é o Score exato da Threat Intel Global e o que isso indica?
- Correlação: Como essas peças comprovam (ou refutam) a recomendação do RAG?

EXEMPLO 1: Concordância e Zero-Day]
{
  "avaliacoes": [
    {
      "id_alvo": "185.15.20.50",
      "padrao_ataque": "ST-ALIGN | ESPAÇO: [FOCADO] | TEMPO: [BURST AGUDO] Taxa de 50.0 ev/s | FW-SEVERIDADE: HIGH | FW-THREAT: RedTeam-Attack | [🌍 THREAT INTEL: LIMPO] O IP tem Score 0%.",
      "dica_rag": "Ameaça Crítica. Recomenda-se BLOQUEAR.",
      "analise_contexto": "Fatos Internos: O tráfego apresenta TEMPO [BURST AGUDO] com 50.0 ev/s e ESPAÇO [FOCADO]. O firewall emitiu alertas críticos explícitos: FW-SEVERIDADE: HIGH e FW-THREAT: RedTeam-Attack.\nFatos Externos: A Threat Intel aponta IP [🌍 THREAT INTEL: LIMPO] com Score 0%.\nCorrelação: Apesar do histórico limpo externo (Score 0%), os alertas severos do equipamento físico comprovam um ataque ativo. A divergência aponta inegavelmente para um ataque do tipo Zero-Day.",
      "justificativa": "Evidências físicas de anomalia volumétrica e alertas HIGH do firewall sobrepõem o histórico limpo externo da API. Ação preventiva mandatória para conter o Zero-Day.",
      "veredito": "BLOQUEAR",
      "nivel_confianca": "ALTA"
    }
  ]
}

[INSTRUÇÃO PARA O LOTE ATUAL]
Gere as avaliações para o lote fornecido usando a estrutura JSON requerida. RESPEITE AS REGRAS DE ANTI-ALUCINAÇÃO.
"""

        prompt_usuario_json = json.dumps(lista_incidentes, ensure_ascii=False, indent=2)
        
        prompt_usuario = f"""Abaixo está um Lote de {len(lista_incidentes)} IPs que entraram no seu radar neste segundo.
Retorne um ÚNICO objeto JSON respondendo a todos eles, OBRIGATORIAMENTE contendo a chave root "avaliacoes".

INCIDENTES EM REDE:
{prompt_usuario_json}
"""

        # 🔥 A OPÇÃO NUCLEAR: Structured Outputs (Esquema JSON Forçado)
        # O Ollama será fisicamente impedido de ignorar qualquer uma destas chaves.
        esquema_forcado = {
            "type": "object",
            "properties": {
                "avaliacoes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id_alvo": {"type": "string"},
                            "padrao_ataque": {"type": "string"},
                            "dica_rag": {"type": "string"},
                            "analise_contexto": {"type": "string"},
                            "justificativa": {"type": "string"},
                            "veredito": {"type": "string"},
                            "nivel_confianca": {"type": "string"}
                        },
                        "required": [
                            "id_alvo", "padrao_ataque", "dica_rag", 
                            "analise_contexto", "justificativa", "veredito", "nivel_confianca"
                        ]
                    }
                }
            },
            "required": ["avaliacoes"]
        }

        # Payload formatado perfeitamente para a API nativa do Ollama Local
        payload = {
            "model": self.MODELO,
            "system": prompt_sistema,
            "prompt": prompt_usuario,
            "format": esquema_forcado,
            "stream": False,
            "keep_alive": self.OLLAMA_KEEP_ALIVE,
            "options": {
                "temperature": 0.0
            }
        }

        tentativas = 0
        max_tentativas = 3
        while tentativas < max_tentativas:
            try:
                t0_local = time.time()
                
                # Dispara o log para a placa de vídeo local via Ollama
                resposta = requests.post(self.OLLAMA_URL, json=payload, timeout=180)
                resposta.raise_for_status() 
                
                dados = resposta.json()
                texto_resposta = dados.get("response", "")
                
                t_total = time.time() - t0_local
                
                # Conversão do tempo de nanosegundos (Ollama) para segundos
                metricas_ia = {
                    "total_duration": dados.get("total_duration", 0) / 1e9,
                    "prompt_eval_count": dados.get("prompt_eval_count", 0),
                    "eval_count": dados.get("eval_count", 0),
                    "eval_duration": dados.get("eval_duration", 0) / 1e9
                }
                
                return texto_resposta, prompt_sistema, prompt_usuario_json, metricas_ia
                
            except Exception as e:
                tentativas += 1
                logger.error(f"Falha na API Local do Ollama: {e}. Tentativa {tentativas}...")
                time.sleep(2)
                
        return '{"avaliacoes": []}', prompt_sistema, prompt_usuario_json, {}

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1, metricas_lote=None, borda_blacklist=None):
        relatorio_processado = RelatorioTriagem()
        dados_sft = []
        
        incidentes_para_ia = []
        mapa_hashes = {}
        mapa_is_red_team = {}  
        
        if metricas_lote is None:
            metricas_lote = {}
        metricas_lote["total_incidentes"] = len(relatorio_triagem_input.incidentes)
        metricas_lote["cache_hits"] = 0
        metricas_lote["cache_misses"] = 0

        # ==========================================================
        # 1. TRIAGEM PELO CACHE SEMÂNTICO
        # ==========================================================
        for inc in relatorio_triagem_input.incidentes:
            
            mapa_is_red_team[inc.id_alvo] = inc.is_red_team
            
            padrao_limpo = re.sub(r'EVENTOS TOTAIS HOJE: \d+ \| ', '', inc.padrao_ataque)
            padrao_limpo = re.sub(r'Taxa atual de [\d.]+ ev/s\.', 'Taxa atual de X ev/s.', padrao_limpo)
            padrao_limpo = re.sub(r'Upload de [\d.]+ Megabytes', 'Upload de X Megabytes', padrao_limpo)
            padrao_limpo = re.sub(r'tocou \d+ IPs', 'tocou X IPs', padrao_limpo)
            
            assinatura = f"{padrao_limpo}|{inc.dica_rag}".encode('utf-8')
            hash_inc = hashlib.md5(assinatura).hexdigest()

            if hash_inc in self.cache_decisoes:
                logger.info(f"⚡ [CACHE HIT] Reciclando veredito para IP {inc.id_alvo}.")
                inc_cache = Incidente.model_validate_json(self.cache_decisoes[hash_inc])
                inc_cache.justificativa = "[CACHE] " + inc_cache.justificativa 
                relatorio_processado.incidentes.append(inc_cache)
                metricas_lote["cache_hits"] += 1
            else:
                # ==========================================================
                # 🔥 INTEGRAÇÃO MCP: ENRIQUECIMENTO DE CONTEXTO GLOBAL
                # ==========================================================
                padrao_enriquecido = inc.padrao_ataque
                
                # Só chamamos a API externa se não for tráfego local (10.x, 192.168.x)
                if not inc.id_alvo.startswith(("10.", "192.168.", "172.")):
                    # Consultamos a ficha do IP na nuvem
                    ficha_criminal = self.mcp_intel.consultar_ip(inc.id_alvo)
                    
                    # Anexamos a ficha criminal no log para a IA ler!
                    padrao_enriquecido += f" | {ficha_criminal}"

                inc_dict = {
                    "id_alvo": inc.id_alvo,
                    "padrao_ataque": padrao_enriquecido,  # <--- Aqui entra o dado enriquecido!
                    "dica_rag": inc.dica_rag,
                    # Preenche as lacunas para guiar modelos menores (Skeleton Prompting)
                    "analise_contexto": "",
                    "justificativa": "",
                    "veredito": "",
                    "nivel_confianca": ""
                }
                incidentes_para_ia.append(inc_dict)
                mapa_hashes[inc.id_alvo] = hash_inc 
                metricas_lote["cache_misses"] += 1

        # ==========================================================
        # 2. INFERÊNCIA EM LOTE E CHAIN-OF-THOUGHT
        # ==========================================================
                TAMANHO_LOTE = 3 
        
        for i in range(0, len(incidentes_para_ia), TAMANHO_LOTE):
            chunk = incidentes_para_ia[i:i + TAMANHO_LOTE]
            logger.info(f"🧠 [BATCH CoT] Raciocinando sobre {len(chunk)} ameaças inéditas simultaneamente...")
            
            resposta_ia_str, prompt_sistema, prompt_usuario, metricas_ia = self._consultar_ia_batch(chunk)
            
            for k, v in metricas_ia.items():
                metricas_lote[k] = metricas_lote.get(k, 0) + v
            
            try:
                json_parseado = json.loads(resposta_ia_str)
                lista_avaliacoes = json_parseado.get("avaliacoes", [])
                
                mapa_reconstrucao = {inc_dict["id_alvo"]: inc_dict for inc_dict in chunk}
                
                for avaliacao in lista_avaliacoes:
                    ip_recebido = avaliacao.get("id_alvo")
                    input_original = mapa_reconstrucao.get(ip_recebido, {})
                    
                    avaliacao.setdefault("padrao_ataque", input_original.get("padrao_ataque", "N/A"))
                    avaliacao.setdefault("dica_rag", input_original.get("dica_rag", "N/A"))
                    
                    inc_decidido = Incidente(**avaliacao)
                    
                    hash_deste_incidente = mapa_hashes.get(inc_decidido.id_alvo)
                    if hash_deste_incidente:
                        self.cache_decisoes[hash_deste_incidente] = inc_decidido.model_dump_json()

                    inc_decidido.justificativa += f" (Por {self.MODELO.upper()})"
                    relatorio_processado.incidentes.append(inc_decidido)
                
                if lista_avaliacoes:
                    linha_sft = {"messages": [
                        {"role": "system", "content": prompt_sistema},
                        {"role": "user", "content": prompt_usuario},
                        {"role": "assistant", "content": resposta_ia_str}
                    ]}
                    dados_sft.append(json.dumps(linha_sft, ensure_ascii=False) + "\n")
                    
            except (json.JSONDecodeError, ValidationError) as e:
                logger.error(f"Falha ao processar o Batch: {e}")

        # ==========================================================
        # 3. SALVAR RESULTADOS
        # ==========================================================
        t0_io = time.time()
        
        novas_decisoes = []
        for i in relatorio_processado.incidentes:
            d = i.model_dump()
            d["is_red_team"] = mapa_is_red_team.get(i.id_alvo, False)
            novas_decisoes.append(d)
            
            if d.get("veredito") == "BLOQUEAR":
                if borda_blacklist is not None and i.id_alvo not in borda_blacklist:
                    borda_blacklist[i.id_alvo] = time.time()
                    with open(self.ARQUIVO_BLACKLIST, "a", encoding="utf-8") as bf:
                        bf.write(f"{i.id_alvo}\n")
                
        if novas_decisoes:
            with open(self.ARQUIVO_PLAYBOOK, "a", encoding="utf-8") as f:
                for d in novas_decisoes:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
            
        if dados_sft: 
            with open(self.ARQUIVO_SFT, "a", encoding="utf-8") as f:
                f.writelines(dados_sft)
                
        # ==========================================================
        # 4. SALVAR MÉTRICAS (MÓDULO FLUIDO DE TELEMETRIA)
        # ==========================================================
        tempo_io = round(time.time() - t0_io, 4)
        
        metricas_lote["lote"] = num_lote
        metricas_lote["timestamp"] = datetime.now().isoformat()
        metricas_lote["tempo_io_disco"] = tempo_io
        
        if metricas_lote.get("eval_duration", 0) > 0:
            metricas_lote["tps"] = round(metricas_lote.get("eval_count", 0) / metricas_lote["eval_duration"], 2)
        else:
            metricas_lote["tps"] = 0.0
            
        with open(self.ARQUIVO_METRICAS, "a", encoding="utf-8") as f:
            f.write(json.dumps(metricas_lote, ensure_ascii=False) + "\n")