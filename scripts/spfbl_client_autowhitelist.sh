#!/bin/bash

# ==============================================================================
# SPFBL - Automação de Whitelist (Client Side)
# Detecta cPanel/Exim ou Zimbra/Postfix e configura o autoloader
# ==============================================================================

# Definições
SPFBL_CLIENT_BIN="/usr/local/bin/spfbl.sh"  # Caminho padrão do cliente SPFBL (ajustável)
LOG_FILE="/var/log/spfbl_whitelist_config.log"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%F %T')]${NC} $1"
    echo "[$(date +'%F %T')] $1" >> "$LOG_FILE"
}

die() {
    echo -e "${RED}[ERRO]${NC} $1"
    echo "[$(date +'%F %T')] [ERRO] $1" >> "$LOG_FILE"
    exit 1
}

# Verifica root
if [ "$EUID" -ne 0 ]; then die "Execute como root."; fi

echo -e "${BLUE}=== SPFBL Whitelist Auto-Configuration ===${NC}"
log "Iniciando detecção de ambiente..."

# Verifica se o cliente SPFBL está instalado
if [ ! -f "$SPFBL_CLIENT_BIN" ] && [ ! -f "/usr/bin/spfbl" ]; then
    echo -e "${YELLOW}AVISO: O binário do cliente SPFBL não foi encontrado nos locais padrão.${NC}"
    echo "Por favor, informe onde está o script 'spfbl.sh' ou o binário 'spfbl' (ex: /opt/spfbl/spfbl.sh):"
    read -r CUSTOM_BIN
    if [ -f "$CUSTOM_BIN" ]; then
        SPFBL_CLIENT_BIN="$CUSTOM_BIN"
    else
        die "Binário não encontrado. Instale o cliente SPFBL antes de rodar este script."
    fi
else
    # Se achar em /usr/bin/spfbl prefere ele
    if [ -f "/usr/bin/spfbl" ]; then SPFBL_CLIENT_BIN="/usr/bin/spfbl"; fi
fi

log "Usando cliente SPFBL em: $SPFBL_CLIENT_BIN"

# ==============================================================================
# DETECÇÃO DE AMBIENTE
# ==============================================================================

IS_CPANEL=false
IS_ZIMBRA=false
IS_POSTFIX=false

if [ -d "/usr/local/cpanel" ]; then
    IS_CPANEL=true
    log "Ambiente detectado: cPanel / EXIM"
elif [ -d "/opt/zimbra" ]; then
    IS_ZIMBRA=true
    log "Ambiente detectado: Zimbra"
elif [ -f "/etc/postfix/main.cf" ]; then
    IS_POSTFIX=true
    log "Ambiente detectado: Postfix (Genérico)"
else
    die "Não foi possível detectar cPanel, Zimbra ou Postfix padrão."
fi

# ==============================================================================
# CONFIGURAÇÃO: CPANEL / EXIM
# ==============================================================================
if [ "$IS_CPANEL" = true ]; then
    
    EXIM_SCRIPT="/var/spool/exim/spfbl.sh"
    
    log "Configurando script de transporte em $EXIM_SCRIPT..."
    
    # Cria o script que o Exim vai chamar
    cat <<EOF > "$EXIM_SCRIPT"
#!/bin/bash
# Script de Whitelist Automática SPFBL para cPanel
LOG="/var/spool/exim/log-transport.log"
ARGS="\$1"

# Debug opcional (descomente se precisar)
# echo "\$(date) - Args: \$ARGS" >> "\$LOG"

# Chama o cliente SPFBL
# O >/dev/null garante que o Exim não trave esperando output
$SPFBL_CLIENT_BIN white sender "\$ARGS" >/dev/null 2>&1
EOF

    chmod +x "$EXIM_SCRIPT"
    chown cpaneleximfilter:cpaneleximfilter "$EXIM_SCRIPT" 2>/dev/null || chown mailnull:mail "$EXIM_SCRIPT"
    
    log "Script criado e permissões ajustadas."
    
    echo -e "\n${RED}!!! AÇÃO MANUAL NECESSÁRIA NO WHM !!!${NC}"
    echo "O cPanel gerencia o exim.conf via templates. Adicionar isso via script pode quebrar atualizações."
    echo "Vá em: WHM > Service Configuration > Exim Configuration Manager > Advanced Editor"
    echo ""
    echo -e "${YELLOW}1. Procure a seção [PREROUTERS] e adicione:${NC}"
    echo "--------------------------------------------------------"
    cat <<EOF
whitelister:
  driver = accept
  domains = !+local_domains
  condition = \${if match_domain{\$sender_address_domain}{+local_domains}} 
  condition = \${if or {{ !eq{\$h_list-id:\$h_list-post:\$h_list-subscribe:}{} }{ match{\$h_precedence:}{(?i)bulk|list|junk|auto_reply} } { match{\$h_auto-submitted:}{(?i)auto-generated|auto-replied} } } {no}{yes}}
  transport = whlist
  unseen
EOF
    echo "--------------------------------------------------------"
    
    echo -e "\n${YELLOW}2. Procure a seção [TRANSPORTSTART] e adicione:${NC}"
    echo "--------------------------------------------------------"
    cat <<EOF
whlist:
  driver = pipe
  command = $EXIM_SCRIPT \$local_part@\$domain 
  return_fail_output = true
  ignore_status = true
  user = cpaneleximfilter
  group = cpaneleximfilter
EOF
    echo "--------------------------------------------------------"
    log "Instruções cPanel exibidas."

# ==============================================================================
# CONFIGURAÇÃO: ZIMBRA / POSTFIX
# ==============================================================================
elif [ "$IS_ZIMBRA" = true ] || [ "$IS_POSTFIX" = true ]; then

    SCRIPT_PATH="/usr/local/sbin/spfbl_whitelist_cron.sh"
    MAILLOG="/var/log/maillog"
    
    # Tenta achar o log correto se não for o padrão
    if [ ! -f "$MAILLOG" ]; then
        if [ -f "/var/log/mail.log" ]; then MAILLOG="/var/log/mail.log"; fi
        if [ -f "/var/log/zimbra.log" ]; then MAILLOG="/var/log/zimbra.log"; fi
    fi

    log "Log de correio detectado: $MAILLOG"
    log "Criando script de análise em $SCRIPT_PATH..."

    # Script refinado (Melhor que o original: usa mktemp e caminhos absolutos)
    cat <<EOF > "$SCRIPT_PATH"
#!/bin/bash
# Autor: Kleber Rodrigues / Automatizado por Script
SHELL=/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Define variáveis de data para o grep (Formato syslog: Feb 18 10)
MES=\$(date +%b)
DIA=\$(date +%_d)
HORA=\$(date +%H)
LOGFILE="$MAILLOG"
TEMP_FILE=\$(mktemp)

# Filtra o log
# 1. Pega a hora atual
# 2. Pega status=sent (sucesso)
# 3. Extrai o email de destino (to=<...>)
# 4. Limpa formatação
grep "\$MES \$DIA \$HORA" "\$LOGFILE" | \
grep "status=sent" | \
grep -o "to=<.*.>," | \
cut -d '<' -f 2 | cut -d '>' -f 1 | \
sort -u > "\$TEMP_FILE"

# Processa cada email encontrado
while read -r EMAIL; do
    if [[ -n "\$EMAIL" ]]; then
        # Chama o SPFBL para adicionar na whitelist
        $SPFBL_CLIENT_BIN white sender "\$EMAIL" >/dev/null 2>&1
    fi
done < "\$TEMP_FILE"

# Limpeza
rm -f "\$TEMP_FILE"
EOF

    chmod +x "$SCRIPT_PATH"
    log "Script de análise criado."

    # Configurando o Cronjob
    CRON_CMD="$SCRIPT_PATH"
    log "Configurando Crontab..."
    
    if crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        log "Crontab já possui a entrada."
    else
        # Roda todo minuto 59 de cada hora
        (crontab -l 2>/dev/null; echo "59 * * * * $SCRIPT_PATH") | crontab -
        log "Agendamento adicionado ao Crontab (roda no minuto 59 de cada hora)."
    fi

    echo -e "${GREEN}Configuração para Zimbra/Postfix concluída!${NC}"
    echo "O script lerá o $MAILLOG a cada hora e adicionará os destinatários na whitelist."
fi

log "Fim da execução."