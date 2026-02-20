#!/bin/bash

# ==============================================================================
# SPFBL - Automação de Whitelist (Client Side)
# Detecta cPanel/Exim ou Zimbra/Postfix e configura automação conforme wiki.
# ==============================================================================

: "${SPFBL_CLIENT_BIN:=/usr/local/bin/spfbl.sh}"
: "${LOG_FILE:=/var/log/spfbl_whitelist_config.log}"
: "${WHITELIST_CRON_SCHEDULE:=*/15 * * * *}"
: "${SPFBL_SERVER_IP:=127.0.0.1}"
: "${SPFBL_SERVER_HOSTNAME:=localhost}"
: "${SPFBL_POLICY_PORT:=9877}"
: "${SPFBL_ADMIN_PORT:=9875}"
: "${SPFBL_AUTOWHITELIST_NONINTERACTIVE:=1}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ENVIRONMENT=""

log() {
    echo -e "${GREEN}[$(date +'%F %T')]${NC} $1"
    echo "[$(date +'%F %T')] $1" >> "$LOG_FILE"
}

die() {
    echo -e "${RED}[ERRO]${NC} $1"
    echo "[$(date +'%F %T')] [ERRO] $1" >> "$LOG_FILE"
    exit 1
}

require_root() {
    [ "$EUID" -eq 0 ] || die "Execute como root."
}

resolve_client_bin() {
    if [ -x "/usr/bin/spfbl" ]; then
        SPFBL_CLIENT_BIN="/usr/bin/spfbl"
        return 0
    fi

    if [ -x "$SPFBL_CLIENT_BIN" ]; then
        return 0
    fi

    if [ "$SPFBL_AUTOWHITELIST_NONINTERACTIVE" = "1" ]; then
        die "Cliente SPFBL não encontrado. Defina SPFBL_CLIENT_BIN e rode novamente."
    fi

    echo -e "${YELLOW}AVISO:${NC} Cliente SPFBL não encontrado nos locais padrão."
    echo "Informe o caminho do binário (ex.: /usr/bin/spfbl):"
    read -r CUSTOM_BIN
    [ -x "$CUSTOM_BIN" ] || die "Binário inválido: $CUSTOM_BIN"
    SPFBL_CLIENT_BIN="$CUSTOM_BIN"
}

detect_environment() {
    if [ -d "/usr/local/cpanel" ]; then
        ENVIRONMENT="cpanel"
        log "Ambiente detectado: cPanel / Exim"
        return
    fi

    if [ -d "/opt/zimbra" ]; then
        ENVIRONMENT="zimbra"
        log "Ambiente detectado: Zimbra"
        return
    fi

    if [ -f "/etc/postfix/main.cf" ]; then
        ENVIRONMENT="postfix"
        log "Ambiente detectado: Postfix (Genérico)"
        return
    fi

    die "Não foi possível detectar cPanel, Zimbra ou Postfix padrão."
}

check_spfbl_connectivity() {
    if command -v nc >/dev/null 2>&1; then
        if ! nc -z "$SPFBL_SERVER_IP" "$SPFBL_POLICY_PORT" >/dev/null 2>&1; then
            log "Aviso: SPFBL em $SPFBL_SERVER_IP:$SPFBL_POLICY_PORT ainda não responde. Continuando configuração."
        fi
        return
    fi

    if command -v ncat >/dev/null 2>&1; then
        if ! ncat -z "$SPFBL_SERVER_IP" "$SPFBL_POLICY_PORT" >/dev/null 2>&1; then
            log "Aviso: SPFBL em $SPFBL_SERVER_IP:$SPFBL_POLICY_PORT ainda não responde. Continuando configuração."
        fi
    fi
}

configure_cpanel() {
    local exim_script="/var/spool/exim/autoWH"

    log "Configurando script de transporte em $exim_script..."
    cat <<EOF > "$exim_script"
#!/bin/sh
# Debug:
echo "Args recebidos: \$1 = \$1" >> /var/spool/exim/log-transport.log
# Magica:
#/var/spool/exim/spfbl.sh white sender \$1 >/dev/null 2>&1
#echo "WHITE SENDER \$1" | nc $SPFBL_SERVER_HOSTNAME $SPFBL_POLICY_PORT
$SPFBL_CLIENT_BIN white sender \$1
EOF

    chmod +x "$exim_script"
    chown cpaneleximfilter:cpaneleximfilter "$exim_script" 2>/dev/null || chown mailnull:mail "$exim_script"

    echo -e "\n${RED}!!! AÇÃO MANUAL NECESSÁRIA NO WHM !!!${NC}"
    echo "Vá em: WHM > Service Configuration > Exim Configuration Manager > Advanced Editor"
    echo -e "${YELLOW}SECTION: PREROUTERS${NC}"
    cat <<EOF
whitelister:
  driver    = accept
  domains    = !+local_domains
  condition = \${if match_domain{\$sender_address_domain}{+local_domains}} 
  condition = \${if or {{ !eq{\$h_list-id:\$h_list-post:\$h_list-subscribe:}{} }{ match{\$h_precedence:}{(?i)bulk|list|junk|auto_reply} } { match{\$h_auto-submitted:}{(?i)auto-generated|auto-replied} } } {no}{yes}}
  transport = whlist
unseen
EOF
    echo -e "${YELLOW}SECTION: TRANSPORTSTART${NC}"
    cat <<EOF
whlist:
  driver  = pipe
  command = $exim_script \$local_part@\$domain 
  return_fail_output = true
  ignore_status = true 
  #A opção "ignore_status" evita o envio de e-mails para todos os clientes do servidor quando o SPFBL está offline. Autor: Jefferson André Voigt
EOF
    echo
    echo "\"Lembre-se de substituir 'IP-DO-SEU-POOL-SPFBL' pelo seu pool de SPFBL. No caso do matrix defense, seria 'matrix.spfbl.net'.\""
    echo "Neste servidor, o hostname SPFBL detectado foi: $SPFBL_SERVER_HOSTNAME"
    log "Instruções cPanel exibidas."
}

resolve_maillog() {
    if [ -f "/var/log/maillog" ]; then
        echo "/var/log/maillog"
        return
    fi
    if [ -f "/var/log/mail.log" ]; then
        echo "/var/log/mail.log"
        return
    fi
    if [ -f "/var/log/zimbra.log" ]; then
        echo "/var/log/zimbra.log"
        return
    fi
    die "Nenhum log de e-mail encontrado (/var/log/maillog, /var/log/mail.log, /var/log/zimbra.log)."
}

write_postfix_zimbra_script() {
    local script_path="$1"
    local maillog="$2"

    cat <<EOF > "$script_path"
#!/bin/bash
SHELL=/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin

MES=\$(date +%b)
DIA=\$(date +%_d)
HORA=\$(date +%H)
LOGFILE="$maillog"
TEMP_FILE=\$(mktemp)
SPFBL_BIN="$SPFBL_CLIENT_BIN"

grep "\$MES \$DIA \$HORA" "\$LOGFILE" | \
grep "status=sent (250 2.6.0" | \
grep -oE "to=<[^>]+>," | \
grep -oE "@[^>,]+" | \
sort -u > "\$TEMP_FILE"

if [ ! -s "\$TEMP_FILE" ]; then
    grep "\$MES \$DIA \$HORA" "\$LOGFILE" | \
    grep "status=sent" | \
    grep -oE "to=<[^>]+>," | \
    grep -oE "@[^>,]+" | \
    sort -u > "\$TEMP_FILE"
fi

while read -r DOMAIN; do
    if [ -n "\$DOMAIN" ]; then
        "\$SPFBL_BIN" white sender "\$DOMAIN" >/dev/null 2>&1
    fi
done < "\$TEMP_FILE"

rm -f "\$TEMP_FILE"
EOF
}

ensure_cron_job() {
    local cron_job="$1"
    local current_cron

    current_cron="$(crontab -l 2>/dev/null || true)"
    if printf '%s\n' "$current_cron" | grep -Fqx "$cron_job"; then
        log "Crontab já possui a entrada."
        return
    fi

    (printf '%s\n' "$current_cron"; echo "$cron_job") | awk 'NF && !seen[$0]++' | crontab -
    log "Agendamento adicionado ao Crontab ($WHITELIST_CRON_SCHEDULE)."
}

configure_postfix_zimbra() {
    local script_path="/usr/local/sbin/spfbl_whitelist_cron.sh"
    local maillog
    local cron_job

    maillog="$(resolve_maillog)"
    log "Log de correio detectado: $maillog"
    log "Criando script de análise em $script_path..."

    write_postfix_zimbra_script "$script_path" "$maillog"
    chmod +x "$script_path"

    cron_job="$WHITELIST_CRON_SCHEDULE $script_path"
    ensure_cron_job "$cron_job"

    echo -e "${GREEN}Configuração para Zimbra/Postfix concluída!${NC}"
    echo "Agenda: '$WHITELIST_CRON_SCHEDULE' | SPFBL: $SPFBL_SERVER_HOSTNAME ($SPFBL_SERVER_IP)"
}

main() {
    require_root
    echo -e "${BLUE}=== SPFBL Whitelist Auto-Configuration ===${NC}"
    log "Iniciando detecção de ambiente..."

    resolve_client_bin
    log "Usando cliente SPFBL em: $SPFBL_CLIENT_BIN"
    log "Servidor SPFBL: $SPFBL_SERVER_HOSTNAME ($SPFBL_SERVER_IP) policy:$SPFBL_POLICY_PORT admin:$SPFBL_ADMIN_PORT"

    check_spfbl_connectivity
    detect_environment

    case "$ENVIRONMENT" in
        cpanel) configure_cpanel ;;
        zimbra|postfix) configure_postfix_zimbra ;;
        *) die "Ambiente não suportado: $ENVIRONMENT" ;;
    esac

    log "Fim da execução."
}

main "$@"
