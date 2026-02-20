#!/bin/bash
set -euo pipefail
umask 022

# ==============================================================================
# Instalador SPFBL [modular]
# ==============================================================================

# ------------------------------------------------------------------------------
# Configurações e Variáveis
# ------------------------------------------------------------------------------

# Diretorio de instalação do SPFBL
INSTALL_DIR="/opt/spfbl"

# Arquivos de log para monitorar a instalação e os comandos executados
LOG_FILE="/var/log/spfbl_install.log"

# Arquivo de log específico para os comandos executados durante a instalação, para facilitar a depuração em caso de falhas
CMD_LOG="/var/log/spfbl_cmd.log"

# ------------------------------------------------------------------------------
# Configurações do SPBL e do ambiente
# ------------------------------------------------------------------------------

# Diretorio temporário para a instalação, onde os arquivos serão baixados e preparados antes de serem movidos para o diretório final de instalação. Isso ajuda a manter o processo organizado e evita que arquivos temporários sejam misturados com os arquivos finais.
TEMP_SPFBLDIR="/tmp/spfbl_inst"

# Diretorio para o comando spfbl.sh, que é o wrapper do cliente CLI, para facilitar o acesso global ao comando sem precisar do caminho completo
# Você pod mover para qualquer outro diretorio o wrapper vai apontar para o script original na pasta de instalação, mas o ideal é deixar em /usr/local/bin para seguir as convenções do sistema e evitar conflitos com outros comandos
SPFBL_BIN="/usr/local/bin"

# Email do administrador para contato e notificações, que pode ser usado para configurar alertas ou para exibir informações de contato no painel de administração do SPFBL. O script não utiliza diretamente esse email, mas ele pode ser referenciado em futuras implementações ou configurações do SPFBL para garantir que os administradores tenham um ponto de contato claro para questões relacionadas ao software.
SPFBL_ADMIN_EMAIL="postmaster@domain.com"

# Email de abuso para contato em caso de detecção de atividades maliciosas ou abusivas, que pode ser usado para configurar alertas ou para exibir informações de contato no painel de administração do SPFBL. O script não utiliza diretamente esse email, mas ele pode ser referenciado em futuras implementações ou configurações do SPFBL para garantir que haja um ponto de contato claro para relatar atividades suspeitas ou abusivas detectadas pelo software.
SPFBL_ABUSE_EMAIL="abuse@domain.com"

# Senha do administrador para acesso ao painel de administração do SPFBL, que é necessária para garantir a segurança do acesso ao painel e para proteger as configurações e dados do SPFBL contra acessos não autorizados. O script não utiliza diretamente essa senha, mas ela pode ser referenciada em futuras implementações ou configurações do SPFBL para garantir que o acesso ao painel de administração seja protegido por uma senha forte e segura.
# Insira uma senha ou deixe em branco para o sistema gerar uma nova
SPFBL_ADMIN_PASSWORD=""

# Portas do SPFBL:
# - SPFBL_WEB_HTTP_PORT: painel web (http_port no spfbl.conf)
# - SPFBL_WEB_HTTPS_PORT: painel web TLS (https_port no spfbl.conf)
# - SPFBL_FRONT_HTTP_PORT: admin TCP (admin_port no spfbl.conf)
# - SPFBL_BACKEND_HTTP_PORT: policy TCP (spfbl_port no spfbl.conf)
SPFBL_WEB_HTTP_PORT="80"
SPFBL_WEB_HTTPS_PORT="443"
SPFBL_FRONT_HTTP_PORT="9875"
SPFBL_FRONT_HTTPS_PORT="9876"
SPFBL_BACKEND_HTTP_PORT="9877"
SPFBL_BACKEND_HTTPS_PORT="9878"

# Configuração do DNS resolver para o SPFBL, que é necessário para que o SPFBL possa realizar consultas DNS para verificar registros SPF, realizar verificações de blacklist e outras operações relacionadas ao DNS. O script irá configurar o SPFBL para usar esse endereço IP como o resolver DNS principal, garantindo que as consultas DNS sejam direcionadas para esse servidor. Certifique-se de que esse endereço IP seja um servidor DNS válido e acessível a partir do servidor onde o SPFBL está instalado para garantir que as funcionalidades relacionadas ao DNS do SPFBL funcionem corretamente.

# Lista de resolvers
# 1.1.1.1
SPFBL_DNS_RESOLVER_PRIMARY="8.8.8.8"
#SPFBL_DNS_RESOLVER_SECONDARY="1.1.1.1"

# Rede interna local para liberação
SPFBL_CLIENT_CIDR="127.0.0.1/32"

# Hostname ou Label para liberação, que pode ser usado para identificar o cliente ou a rede que está sendo liberada no SPFBL.
SPFBL_CLIENT_LABEL=""

# Lista de servidores autorizados no formato completo:
# "CIDR:identificador:contato@email"
AUTHORIZED_SERVERS=()

# Lista simplificada (somente IP ou CIDR). Ex: "203.0.113.10" ou "203.0.113.0/24"
AUTHORIZED_SERVERS_SIMPLE=()

# Compatibilidade com scripts antigos (mesmo formato de AUTHORIZED_SERVERS)
POLICY_CLIENTS=()

# E-mail opcional para registro automático no instalador DirectAdmin remoto.
DIRECTADMIN_CLIENT_EMAIL=""

# Confirma se sera utilizado TLS para o painel de administração do SPFBL, o que é recomendado para garantir a segurança das conexões ao painel. Se configurado como "yes", o script irá configurar o SPFBL para usar TLS/SSL para o painel de administração, e os usuários deverão acessar o painel através do endereço https://hostname:SPFBL_FRONT_HTTPS_PORT/. Certifique-se de que os certificados TLS/SSL estejam configurados corretamente no servidor para garantir que as conexões seguras funcionem sem problemas.
SPFBL_HTTP_USE_TLS="no"

# Configuração para contribuir com o projeto SPFBL, que pode ser usada para indicar se o usuário deseja enviar dados de uso anônimos para os desenvolvedores do SPFBL para ajudar na melhoria do software. Se configurado como "true", o script pode incluir uma etapa para solicitar a permissão do usuário para enviar dados de uso anônimos, e se o usuário concordar, o script pode configurar o SPFBL para enviar esses dados de forma segura e anônima. Essa configuração é opcional e pode ser ajustada de acordo com as preferências do usuário.
SPFBL_CONTRIBUTE="true"

# Configurações de Localidade e Timezone
LOCALE="pt_BR"
TIMEZONE="America/Sao_Paulo"

# Configurações desejadas (Pode manter o 'm' aqui, o script limpa abaixo)
: "${JAVA_MIN_HEAP:=1024m}"
: "${JAVA_MAX_HEAP:=2048m}"
: "${WHITELIST_CRON_SCHEDULE:=*/15 * * * *}"
: "${SPFBL_JVM_AUTO_TUNE:=yes}"
: "${SPFBL_JVM_MIN_MEMORY:=}"
: "${SPFBL_JVM_MAX_MEMORY:=}"
: "${EXIM_ENABLE:=yes}"
: "${EXIM_CONFIG_TYPE:=internet site; mail is sent and received directly using SMTP}"
: "${EXIM_LOCAL_INTERFACES:=127.0.0.1}"
: "${EXIM_SMTP_PORT:=587}"
: "${MAIL_DOMAIN:=}"
: "${FIREWALL_AUTO_CONFIG:=no}"
: "${SPFBL_TLS_SELF_SIGNED:=yes}"
: "${SPFBL_TLS_SELF_SIGNED_DAYS:=365}"
: "${SPFBL_STARTUP_TIMEOUT:=300}"
: "${SPFBL_AUTOWHITELIST_ENABLE:=yes}"
: "${SPFBL_AUTOWHITELIST_REQUIRED:=no}"
: "${DIRECTADMIN_INTEGRATION_ENABLE:=yes}"
: "${CPANEL_INTEGRATION_ENABLE:=yes}"
: "${CHILD_CPANEL_INSTALLER_VERSION:=1.1.0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Repositorio oficial do SPFBL para baixar o código fonte caso os arquivos não estejam presentes no diretório de origem. O script irá clonar o repositório para um diretório temporário e usar os arquivos de lá para a instalação, garantindo que a instalação seja feita com os arquivos mais recentes do repositório oficial, caso eles não estejam disponíveis localmente.

SPFBL_REPO="https://github.com/leonamp/SPFBL/"

# Fork pessoal para testes, caso queira usar o código do fork ao invés do repositório oficial, basta substituir a URL abaixo pelo link do seu fork. O script irá clonar o repositório do fork e usar os arquivos de lá para a instalação, permitindo que você teste suas modificações ou use uma versão personalizada do SPFBL sem precisar alterar o código do script de instalação.
#SPFBL_REPO="https://github.com/sr00t3d/SPFBL"

# Insira aqui o hostname do servidor caso queira configurar manualmente, ou deixe vazio para que o script tente resolver automaticamente. O script irá validar o hostname e garantir que seja um FQDN válido, além de configurar a URL de acesso ao painel de administração com base nesse hostname. Se o hostname não for válido, o script irá abortar a instalação e solicitar que o usuário configure um hostname válido antes de prosseguir.
REAL_HOSTNAME=""

# Insira aqui o caminho do binário do java caso queira configurar manualmente, ou deixe vazio para que o script tente detectar automaticamente. O script irá verificar se o comando 'java' está disponível no PATH e, se não estiver, tentará instalar o Java via APT. Se ainda assim não conseguir encontrar o Java, ele irá baixar e instalar manualmente uma versão do JDK 17. Após a instalação, o script irá validar se o Java está acessível e configurará o caminho correto no script de inicialização do serviço para garantir que o SPFBL seja executado com a JVM correta. Se o Java não for encontrado ou instalado corretamente, o script irá abortar a instalação e solicitar que o usuário resolva o problema do Java antes de prosseguir, já que o SPFBL depende do Java para funcionar corretamente.
JAVA_PATH=""

# Para container em Docker sem systemd, forçamos o uso do init.d para evitar falhas na configuração do serviço. O script tentará usar systemd se disponível, mas se detectar que está rodando em um ambiente sem systemd (como um container), ele irá automaticamente usar o método init.d para garantir a compatibilidade.
USE_SYSTEMD=false
SERVER_INTERFACE=""
SERVER_IP=""
PUBLIC_IP=""
IS_PRIVATE_NETWORK="unknown"
BUILD_TMP_DIR=""

# Cores do sistema de log para melhorar a legibilidade dos logs e mensagens de status durante a instalação. O script utiliza cores para destacar mensagens de erro, sucesso e avisos, facilitando a identificação rápida do status de cada etapa do processo de instalação.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
echo -e "
                                                           
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄   ▄▄▄                  
█████▀▀▀ ███▀▀███▄ ███▀▀▀▀▀ ███▀▀███▄ ███             ██   
 ▀████▄  ███▄▄███▀ ███▄▄    ███▄▄███▀ ███      ▄█▀█▄ ▀██▀▀ 
   ▀████ ███▀▀▀▀   ███▀▀    ███  ███▄ ███      ██▄█▀  ██   
███████▀ ███       ███      ████████▀ ████████ ▀█▄▄▄  ██   
                                                           

Versão: 1.0 (beta)      
Node: Master - Versão SPFBL
Hostname: $REAL_HOSTNAME                                                                                     
"
}

# Função de log para registrar mensagens de status e erros no arquivo de log, permitindo que o usuário acompanhe o progresso da instalação e tenha um registro detalhado do processo para referência futura ou para depuração em caso de falhas.
log_msg() {
    local type="$1"
    local msg="$2"
    echo "[$type]: $msg" >> "$LOG_FILE"
}

cleanup() {
    if [ -n "${BUILD_TMP_DIR:-}" ] && [ -d "$BUILD_TMP_DIR" ]; then
        rm -rf "$BUILD_TMP_DIR"
    fi
}
trap cleanup EXIT

# Função die para error handling, que exibe uma mensagem de erro formatada, registra o erro no arquivo de log e exibe as últimas linhas do log de comandos para ajudar na depuração, caso o arquivo de log de comandos exista e contenha informações relevantes. Após exibir a mensagem de erro e as informações de depuração, a função encerra o script com um código de saída indicando falha.
die() {
    echo -e "${RED}[ERRO FATAL]${NC} $1"
    log_msg "!" "ERRO: $1"
    if [ -s "$CMD_LOG" ]; then
        echo -e "${YELLOW}--- Últimas linhas do erro ---${NC}"
        tail -n 20 "$CMD_LOG"
    fi
    exit 1
}

# Spinner para exibir um indicador visual de progresso durante a execução de comandos que podem levar algum tempo, como instalações ou configurações. A função exec_visual recebe uma mensagem descritiva e um comando a ser executado, e exibe um spinner animado enquanto o comando está em execução. Se o comando for bem-sucedido, exibe uma mensagem de sucesso; caso contrário, exibe uma mensagem de falha.
exec_visual() {
    local msg="$1"; shift
    echo -ne "${YELLOW}[PROCESSANDO]${NC} $msg ... "
    "$@" > "$CMD_LOG" 2>&1 &
    local pid=$!
    local delay=0.1
    local spinstr='|/-\\'

    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep "$delay"
        printf "\b\b\b\b\b\b"
    done

    wait "$pid"
    local exit_code=$?
    printf "    \b\b\b\b"

    if [ "$exit_code" -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC}"
        return 0
    fi

    echo -e "${RED}[FALHA]${NC}"
    return "$exit_code"
}

# Função para detectar FQDN válido, garantindo que o hostname configurado seja adequado para uso no painel de administração do SPFBL e para a configuração da URL de acesso. O script verifica se o hostname é não vazio, tem um comprimento adequado, contém pelo menos um ponto (indicando um domínio), não possui pontos consecutivos e que cada rótulo do hostname segue as regras de formatação válidas (começa e termina com um caractere alfanumérico e pode conter hífens no meio). Se o hostname não for válido, a função retorna uma falha, e o script irá abortar a instalação solicitando que o usuário configure um hostname válido antes de prosseguir.
is_valid_hostname() {
    local host="$1"

    [ -n "$host" ] || return 1
    [ "${#host}" -le 253 ] || return 1
    [[ "$host" == *.* ]] || return 1
    [[ "$host" != *..* ]] || return 1

    local IFS='.'
    read -r -a labels <<< "$host"
    [ "${#labels[@]}" -ge 2 ] || return 1

    for label in "${labels[@]}"; do
        [ -n "$label" ] || return 1
        [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

# Detecta IP e porta para verificar se o serviço está respondendo, utilizando netcat (nc) ou ncat, dependendo do que estiver disponível no sistema. A função tcp_check tenta estabelecer uma conexão TCP com o host e porta especificados, e retorna um código de saída indicando sucesso ou falha. Se nenhum dos comandos de verificação estiver disponível, a função retorna uma falha por padrão.
tcp_check() {
    local host="$1"
    local port="$2"

    if command -v nc >/dev/null 2>&1; then
        nc -z "$host" "$port" >/dev/null 2>&1
        return $?
    fi

    if command -v ncat >/dev/null 2>&1; then
        ncat -z "$host" "$port" >/dev/null 2>&1
        return $?
    fi

    return 1
}

wait_for_port() {
    local host="$1"
    local port="$2"
    local timeout="${3:-60}"
    local start elapsed

    start=$(date +%s)
    while true; do
        if tcp_check "$host" "$port"; then
            return 0
        fi
        elapsed=$(( $(date +%s) - start ))
        if [ "$elapsed" -ge "$timeout" ]; then
            return 1
        fi
        sleep 1
    done
}

backup_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    cp -a "$file" "${file}.$(date +'%Y%m%d%H%M%S')~"
}

detect_network() {
    local route_line
    route_line="$(ip route get 1.1.1.1 2>/dev/null | head -n1 || true)"
    SERVER_INTERFACE="$(awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' <<< "$route_line")"
    SERVER_IP="$(awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' <<< "$route_line")"
    SERVER_INTERFACE="${SERVER_INTERFACE:-lo}"
    SERVER_IP="${SERVER_IP:-127.0.0.1}"
    log_msg "*" "Interface detectada: $SERVER_INTERFACE ($SERVER_IP)"
}

detect_public_ip() {
    PUBLIC_IP=""
    if command -v curl >/dev/null 2>&1; then
        PUBLIC_IP="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [ -z "$PUBLIC_IP" ] && command -v wget >/dev/null 2>&1; then
        PUBLIC_IP="$(wget -4 -qO- https://api.ipify.org 2>/dev/null || true)"
    fi
    if [ -z "$PUBLIC_IP" ] && command -v dig >/dev/null 2>&1; then
        PUBLIC_IP="$(dig +short -4 myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -n1 || true)"
    fi
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP="$SERVER_IP"
    fi
    if [[ "$SERVER_IP" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\. ]]; then
        IS_PRIVATE_NETWORK="yes"
    else
        IS_PRIVATE_NETWORK="no"
    fi
    log_msg "*" "IP público detectado: $PUBLIC_IP (rede privada: $IS_PRIVATE_NETWORK)"
}

auto_tune_jvm_memory() {
    local mem_total_kb mem_total_mb cgroup_max_bytes cgroup_max_mb usable_mb min_mb max_mb

    if [ -n "${SPFBL_JVM_MIN_MEMORY:-}" ] && [ -n "${SPFBL_JVM_MAX_MEMORY:-}" ]; then
        JAVA_MIN_HEAP="$SPFBL_JVM_MIN_MEMORY"
        JAVA_MAX_HEAP="$SPFBL_JVM_MAX_MEMORY"
        echo -e "${YELLOW}[CONFIG]${NC} JVM custom: Xms=$JAVA_MIN_HEAP Xmx=$JAVA_MAX_HEAP"
        return 0
    fi

    [ "${SPFBL_JVM_AUTO_TUNE:-yes}" = "yes" ] || return 0

    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    mem_total_mb=$((mem_total_kb / 1024))

    if [ -r /sys/fs/cgroup/memory.max ]; then
        cgroup_max_bytes=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "max")
        if [ "$cgroup_max_bytes" != "max" ] && [ "$cgroup_max_bytes" -gt 0 ] 2>/dev/null; then
            cgroup_max_mb=$((cgroup_max_bytes / 1024 / 1024))
            if [ "$cgroup_max_mb" -gt 0 ] && [ "$cgroup_max_mb" -lt "$mem_total_mb" ]; then
                mem_total_mb="$cgroup_max_mb"
            fi
        fi
    fi

    usable_mb=$((mem_total_mb - 512))
    [ "$usable_mb" -lt 512 ] && usable_mb=512

    min_mb=$((usable_mb * 25 / 100))
    max_mb=$((usable_mb * 70 / 100))

    [ "$min_mb" -lt 512 ] && min_mb=512
    [ "$max_mb" -lt "$min_mb" ] && max_mb="$min_mb"

    JAVA_MIN_HEAP="${min_mb}m"
    JAVA_MAX_HEAP="${max_mb}m"
    echo -e "${YELLOW}[CONFIG]${NC} JVM auto-ajustada: Xms=$JAVA_MIN_HEAP Xmx=$JAVA_MAX_HEAP (RAM efetiva: ${mem_total_mb}MB)"
}

# Detecta usuário root para garantir que o script seja executado com privilégios adequados, já que a instalação e configuração do SPFBL requerem acesso a arquivos de sistema, instalação de pacotes e configuração de serviços, o que geralmente exige privilégios de administrador. Se o script não for executado como root, ele irá exibir uma mensagem de erro e abortar a instalação para evitar falhas ou problemas de permissão durante o processo.
require_root() {
    [ "$EUID" -eq 0 ] || die "Execute como root."
}

# Remove logs antigos e prepara os arquivos de log para a nova instalação, garantindo que o processo de instalação tenha um registro limpo e organizado das mensagens de status, erros e comandos executados. Isso facilita a depuração em caso de falhas e permite que o usuário acompanhe o progresso da instalação de forma clara.
prepare_logs() {
    rm -f "$CMD_LOG"
    touch "$LOG_FILE"
}

# Valida a memoria disponível no sistema em relação às configurações de heap mínimo e máximo definidas para o Java, garantindo que o SPFBL tenha recursos adequados para funcionar corretamente. A função verifica se a memória disponível é suficiente para o heap mínimo exigido e ajusta o heap máximo se ele exceder a memória disponível. Se a configuração de heap mínimo for maior que o heap máximo ajustado, ela também ajusta o heap mínimo para garantir que seja compatível com o heap máximo. Após a validação e ajustes necessários, a função exibe a configuração final de heap para o usuário.
validate_memory_config() {
    local min_val max_val available_mem max_adjusted
    auto_tune_jvm_memory

    min_val=$(echo "$JAVA_MIN_HEAP" | sed 's/[^0-9]//g')
    max_val=$(echo "$JAVA_MAX_HEAP" | sed 's/[^0-9]//g')
    available_mem=$(free -m | awk '/^Mem:/{print $7}')

    if [ "$available_mem" -lt "$min_val" ]; then
        die "Memória disponível (${available_mem}MB) é menor que o mínimo exigido (${JAVA_MIN_HEAP})."
    fi

    if [ "$max_val" -gt "$available_mem" ]; then
        echo -e "${YELLOW}AVISO:${NC} JAVA_MAX_HEAP (${JAVA_MAX_HEAP}) excede RAM disponível (${available_mem}MB)."
        JAVA_MAX_HEAP="${available_mem}m"
        echo -e "${YELLOW}Ajustando JAVA_MAX_HEAP para ${JAVA_MAX_HEAP}.${NC}"
    fi

    max_adjusted=$(echo "$JAVA_MAX_HEAP" | sed 's/[^0-9]//g')
    if [ "$min_val" -gt "$max_adjusted" ]; then
        JAVA_MIN_HEAP="$JAVA_MAX_HEAP"
    fi

    echo -e "${GREEN}Configuração validada: Min=${JAVA_MIN_HEAP} / Max=${JAVA_MAX_HEAP}${NC}"
}

# Resolve o hostname do sistema e valida se é um FQDN válido, garantindo que o hostname configurado seja adequado para uso no painel de administração do SPFBL e para a configuração da URL de acesso. O script tenta resolver o hostname completo usando 'hostname -f' e, se isso falhar, usa 'hostname' como fallback. Em seguida, ele valida o hostname usando a função is_valid_hostname, e se o hostname não for válido, o script irá abortar a instalação solicitando que o usuário configure um hostname válido antes de prosseguir.
resolve_and_validate_hostname() {
    REAL_HOSTNAME=$(hostname -f 2>/dev/null)
    if [ -z "$REAL_HOSTNAME" ] || [ "$REAL_HOSTNAME" = "(none)" ]; then
        REAL_HOSTNAME=$(hostname)
    fi

    is_valid_hostname "$REAL_HOSTNAME" || die "Hostname inválido: '$REAL_HOSTNAME'. Configure um FQDN válido (ex.: mail.seudominio.com)."
}

# Instala dependencias necessárias para o funcionamento do SPFBL, incluindo Java, ferramentas de rede, cron e utilitários de sistema. A função utiliza o comando exec_visual para exibir um indicador visual de progresso durante a instalação das dependências, e registra qualquer falha no processo para facilitar a depuração. Se a instalação de dependências falhar, a função irá abortar a instalação do SPFBL, já que essas dependências são essenciais para o funcionamento correto do software.
install_dependencies() {
    exec_visual "Atualizando apt" apt-get update || die "Falha ao atualizar repositórios apt."
    exec_visual "Instalando dependências" apt-get install wget git ncat nmap procps default-jre chrony cron locales debconf-utils -y || die "Falha ao instalar dependências."
}

configure_exim4() {
    local exim_domain
    local exim_macros

    [ "${EXIM_ENABLE:-yes}" = "yes" ] || {
        echo -e "${YELLOW}[CONFIG]${NC} Instalação do Exim desativada (EXIM_ENABLE=$EXIM_ENABLE)."
        return 0
    }

    exim_domain="${MAIL_DOMAIN:-}"
    if [ -z "$exim_domain" ]; then
        exim_domain="${REAL_HOSTNAME#*.}"
        [ -n "$exim_domain" ] || exim_domain="$REAL_HOSTNAME"
    fi

    echo -e "${YELLOW}[CONFIG]${NC} Instalando e configurando Exim4..."
    exec_visual "Instalando Exim4" apt-get install exim4 exim4-daemon-heavy -y || die "Falha ao instalar Exim4."

    {
        echo "exim4-config exim4/dc_eximconfig_configtype select $EXIM_CONFIG_TYPE"
        echo "exim4-config exim4/dc_other_hostnames string $exim_domain"
        echo "exim4-config exim4/dc_local_interfaces string $EXIM_LOCAL_INTERFACES"
        echo "exim4-config exim4/dc_readhost string"
        echo "exim4-config exim4/dc_relay_domains string"
        echo "exim4-config exim4/dc_relay_nets string"
        echo "exim4-config exim4/dc_smarthost string"
        echo "exim4-config exim4/dc_minimaldns boolean false"
        echo "exim4-config exim4/dc_use_split_config boolean true"
        echo "exim4-config exim4/dc_hide_mailname boolean false"
        echo "exim4-config exim4/dc_mailname_in_oh boolean true"
        echo "exim4-config exim4/dc_localdelivery select mail_spool"
    } | debconf-set-selections

    mkdir -p /etc/exim4/conf.d/main
    cat > /etc/exim4/conf.d/main/02_exim4-config_ports <<EOF
# Porta SMTP customizada pelo instalador SPFBL
.ifdef MAIN_DAEMON_SMTP_PORTS
daemon_smtp_ports = MAIN_DAEMON_SMTP_PORTS
.else
daemon_smtp_ports = $EXIM_SMTP_PORT
.endif
EOF

    exim_macros="/etc/exim4/conf.d/main/01_exim4-config_listmacrosdefs"
    if [ -f "$exim_macros" ]; then
        sed -i '/^MAIN_DAEMON_SMTP_PORTS.*/d' "$exim_macros"
        printf '\nMAIN_DAEMON_SMTP_PORTS = %s\n' "$EXIM_SMTP_PORT" >> "$exim_macros"
    fi

    exec_visual "Atualizando configuração Exim4" update-exim4.conf || die "Falha ao atualizar configuração do Exim4."
    if command -v systemctl >/dev/null 2>&1; then
        exec_visual "Habilitando Exim4" systemctl enable exim4 || true
        exec_visual "Reiniciando Exim4" systemctl restart exim4 || die "Falha ao reiniciar Exim4."
    else
        exec_visual "Reiniciando Exim4" service exim4 restart || die "Falha ao reiniciar Exim4."
    fi

    echo -e "${GREEN}Exim4 configurado${NC} (domínio: $exim_domain, porta SMTP: $EXIM_SMTP_PORT, interface: $EXIM_LOCAL_INTERFACES)."
}

# Verifica o java e garante que ele esteja disponível para o SPFBL, já que o software depende do Java para funcionar corretamente. A função verifica se o comando 'java' está disponível no PATH e, se não estiver, tenta instalar o Java via APT. Se a instalação via APT falhar ou se o comando 'java' ainda não estiver disponível, a função irá baixar e instalar manualmente uma versão do JDK 17. Após a instalação, a função valida se o Java está acessível e configura o caminho correto no script de inicialização do serviço para garantir que o SPFBL seja executado com a JVM correta. Se o Java não for encontrado ou instalado corretamente, a função irá abortar a instalação e solicitar que o usuário resolva o problema do Java antes de prosseguir.
ensure_java() {
    if ! command -v java >/dev/null 2>&1; then
        exec_visual "Tentando Java via APT" apt-get install default-jre -y || true
    fi

    if ! command -v java >/dev/null 2>&1; then
        echo -e "${YELLOW}Java via APT indisponível. Tentando instalação manual...${NC}"
        cd /opt || die "Sem acesso a /opt"
        exec_visual "Baixando JDK 17" wget -q https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz || die "Falha ao baixar JDK manual."
        mkdir -p /usr/lib/jvm
        exec_visual "Extraindo JDK" tar -zxf openjdk-17.0.2_linux-x64_bin.tar.gz -C /usr/lib/jvm/ || die "Falha ao extrair JDK manual."
        [ -f "/usr/lib/jvm/jdk-17.0.2/bin/java" ] && ln -sf /usr/lib/jvm/jdk-17.0.2/bin/java /usr/bin/java
    fi

    JAVA_PATH=$(readlink -f "$(which java)")
    [ -n "$JAVA_PATH" ] || die "Java não encontrado após instalação."
}

# Confirma o download do java e do código fonte do SPFBL, garantindo que os arquivos necessários para a instalação estejam presentes e acessíveis. A função verifica se os arquivos principais do SPFBL estão presentes no diretório de origem, e se não estiverem, ela baixa o código fonte do repositório oficial do SPFBL no GitHub para um diretório temporário. Após garantir que os arquivos estão disponíveis, a função define o diretório de origem para as etapas subsequentes da instalação.
ensure_source_tree() {
    if [ -f "$REPO_SRC_DIR/dist/SPFBL.jar" ] && [ -f "$REPO_SRC_DIR/run/spfbl.conf" ] && [ -f "$REPO_SRC_DIR/client/spfbl.sh" ]; then
        return 0
    fi

    mkdir -p "$TEMP_SPFBLDIR"
    BUILD_TMP_DIR="$(mktemp -d "$TEMP_SPFBLDIR/spfbl-src.XXXXXX")"
    exec_visual "Baixando SPFBL" git clone "$SPFBL_REPO" "$BUILD_TMP_DIR" || die "Falha ao baixar repositório SPFBL."
    REPO_SRC_DIR="$BUILD_TMP_DIR"
}

install_spfbl_files() {
    ensure_source_tree

    mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/history" /var/log/spfbl

    cp -f "$REPO_SRC_DIR/dist/SPFBL.jar" "$INSTALL_DIR/SPFBL.jar"
    cp -f "$REPO_SRC_DIR/run/spfbl.conf" "$INSTALL_DIR/spfbl.conf"
    cp -rf "$REPO_SRC_DIR/lib" "$REPO_SRC_DIR/data" "$REPO_SRC_DIR/web" "$REPO_SRC_DIR/template" "$INSTALL_DIR/"

    cp -f "$REPO_SRC_DIR/run/spfbl-init.sh" "/etc/init.d/spfbl-init.sh"
    sed -i "s|/usr/bin/java|$JAVA_PATH|g" "/etc/init.d/spfbl-init.sh"
    sed -i -E "s#^[[:space:]]*.*java .*SPFBL\.jar.*#    $JAVA_PATH -Xms$JAVA_MIN_HEAP -Xmx$JAVA_MAX_HEAP -jar /opt/spfbl/SPFBL.jar 2>\&1 \&#" "/etc/init.d/spfbl-init.sh"
    chmod +x "/etc/init.d/spfbl-init.sh"

    mkdir -p "$SPFBL_BIN"
    cp -f "$REPO_SRC_DIR/client/spfbl.sh" "$SPFBL_BIN/spfbl.sh"
}

configure_self_signed_tls() {
    local keystore_file alias dname

    [ "${SPFBL_HTTP_USE_TLS:-no}" = "yes" ] || return 0
    [ "${SPFBL_TLS_SELF_SIGNED:-yes}" = "yes" ] || return 0

    if ! command -v keytool >/dev/null 2>&1; then
        echo -e "${YELLOW}Aviso:${NC} 'keytool' não encontrado. TLS autoassinado não foi gerado."
        return 0
    fi

    keystore_file="$INSTALL_DIR/data/${REAL_HOSTNAME}.jks"
    alias="$REAL_HOSTNAME"
    dname="CN=$REAL_HOSTNAME, OU=SPFBL, O=SPFBL, L=Sao Paulo, ST=SP, C=BR"

    mkdir -p "$INSTALL_DIR/data"

    if [ -s "$keystore_file" ]; then
        echo -e "${YELLOW}[CONFIG]${NC} Keystore já existe: $keystore_file"
        return 0
    fi

    echo -e "${YELLOW}[CONFIG]${NC} Gerando certificado TLS autoassinado..."
    keytool -genkeypair \
        -alias "$alias" \
        -keyalg RSA \
        -keysize 2048 \
        -validity "${SPFBL_TLS_SELF_SIGNED_DAYS:-365}" \
        -dname "$dname" \
        -keystore "$keystore_file" \
        -storetype JKS \
        -storepass "$REAL_HOSTNAME" \
        -keypass "$REAL_HOSTNAME" \
        -noprompt >/dev/null 2>&1 || die "Falha ao gerar keystore TLS autoassinado."

    echo -e "${GREEN}Keystore TLS autoassinado gerado${NC}: $keystore_file"
}

configure_files() {
    local conf_file="$INSTALL_DIR/spfbl.conf"
    local web_port_for_url
    local url_scheme

    set_conf_kv() {
        local key="$1"
        local value="$2"
        local escaped

        escaped=$(printf '%s' "$value" | sed 's/[&|]/\\&/g')
        if grep -Eq "^[#[:space:]]*${key}=" "$conf_file"; then
            sed -i -E "s|^[#[:space:]]*${key}=.*|${key}=${escaped}|" "$conf_file"
        else
            echo "${key}=${value}" >> "$conf_file"
        fi
    }

    echo -e "${YELLOW}[CONFIG]${NC} Ajustando spfbl.conf..."
    [ -f "$conf_file" ] || die "Arquivo de configuração não encontrado: $conf_file"

    web_port_for_url="${SPFBL_WEB_HTTP_PORT:-80}"
    url_scheme="http"
    if [ "${SPFBL_HTTP_USE_TLS:-no}" = "yes" ] && [ -n "${SPFBL_WEB_HTTPS_PORT:-}" ]; then
        url_scheme="https"
        web_port_for_url="${SPFBL_WEB_HTTPS_PORT}"
    fi

    set_conf_kv "hostname" "$REAL_HOSTNAME"
    set_conf_kv "url" "${url_scheme}://$REAL_HOSTNAME:${web_port_for_url}/"

    [ -n "${SPFBL_DNS_RESOLVER_PRIMARY:-}" ] && set_conf_kv "dns_provider_primary" "$SPFBL_DNS_RESOLVER_PRIMARY"
    [ -n "${SPFBL_DNS_RESOLVER_SECONDARY:-}" ] && set_conf_kv "dns_provider_secondary" "$SPFBL_DNS_RESOLVER_SECONDARY"

    [ -n "${SPFBL_WEB_HTTP_PORT:-}" ] && set_conf_kv "http_port" "$SPFBL_WEB_HTTP_PORT"
    [ -n "${SPFBL_WEB_HTTPS_PORT:-}" ] && set_conf_kv "https_port" "$SPFBL_WEB_HTTPS_PORT"
    [ -n "${SPFBL_FRONT_HTTP_PORT:-}" ] && set_conf_kv "admin_port" "$SPFBL_FRONT_HTTP_PORT"
    [ -n "${SPFBL_FRONT_HTTPS_PORT:-}" ] && set_conf_kv "admins_port" "$SPFBL_FRONT_HTTPS_PORT"
    [ -n "${SPFBL_BACKEND_HTTP_PORT:-}" ] && set_conf_kv "spfbl_port" "$SPFBL_BACKEND_HTTP_PORT"
    [ -n "${SPFBL_BACKEND_HTTPS_PORT:-}" ] && set_conf_kv "spfbls_port" "$SPFBL_BACKEND_HTTPS_PORT"

    [ -n "${SPFBL_ADMIN_EMAIL:-}" ] && set_conf_kv "admin_email" "$SPFBL_ADMIN_EMAIL"
    [ -n "${SPFBL_ABUSE_EMAIL:-}" ] && set_conf_kv "abuse_email" "$SPFBL_ABUSE_EMAIL"
    [ -n "${SPFBL_CONTRIBUTE:-}" ] && set_conf_kv "advertisement_show" "$SPFBL_CONTRIBUTE"
}

configure_cli() {
    echo -e "${YELLOW}[CONFIG]${NC} Configurando CLI (/usr/bin/spfbl)..."
    sed -i "s/54.233.253.229/127.0.0.1/g" "$SPFBL_BIN/spfbl.sh" 2>/dev/null || true

    cat <<'EOF' > /usr/bin/spfbl
#!/bin/bash
/bin/bash /usr/local/bin/spfbl.sh "$@"
EOF
    chmod +x /usr/bin/spfbl
}

configure_service() {
    echo -e "${YELLOW}[CONFIG]${NC} Configurando Serviço..."
    pkill -f SPFBL.jar >/dev/null 2>&1 || true

    USE_SYSTEMD=false
    if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
        USE_SYSTEMD=true
    fi

    if [ "$USE_SYSTEMD" = true ]; then
        echo -e "   -> Sistema detectado: ${GREEN}Systemd${NC}"
        cat <<EOF > /etc/systemd/system/spfbl.service
[Unit]
Description=SPFBL Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$JAVA_PATH -Xms$JAVA_MIN_HEAP -Xmx$JAVA_MAX_HEAP -jar $INSTALL_DIR/SPFBL.jar
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        exec_visual "Recarregando Daemon" systemctl daemon-reload || USE_SYSTEMD=false
        if [ "$USE_SYSTEMD" = true ]; then
            exec_visual "Habilitando Serviço" systemctl enable spfbl || die "Falha ao habilitar serviço systemd."
            exec_visual "Iniciando SPFBL (Systemd)" systemctl start spfbl || die "Falha ao iniciar SPFBL via systemd."
        fi
    fi

    if [ "$USE_SYSTEMD" = false ]; then
        echo -e "   -> Sistema detectado: ${YELLOW}Init.d / SysVinit${NC}"
        ln -sf "/etc/init.d/spfbl-init.sh" /etc/init.d/spfbl
        chmod 755 /etc/init.d/spfbl

        if command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d spfbl defaults >/dev/null 2>&1 || true
        elif command -v chkconfig >/dev/null 2>&1; then
            chkconfig --add spfbl >/dev/null 2>&1 || true
        fi

        exec_visual "Iniciando SPFBL (Init.d)" /etc/init.d/spfbl start || die "Falha ao iniciar SPFBL via init.d."
    fi
}

wait_for_service() {
    local ready=false
    local policy_port="${SPFBL_BACKEND_HTTP_PORT:-9877}"
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local timeout="${SPFBL_STARTUP_TIMEOUT:-300}"

    echo -ne "${YELLOW}[AGUARDANDO]${NC} Inicializando JVM e Banco de Dados... "
    if wait_for_port 127.0.0.1 "$policy_port" "$timeout"; then
        ready=true
        echo -e "${GREEN}[PRONTO]${NC}"
        return 0
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet spfbl; then
        if tcp_check 127.0.0.1 "$admin_port" || tcp_check 127.0.0.1 "$web_port"; then
            ready=true
            echo -e "${YELLOW}[PARCIAL]${NC}"
            echo "Serviço ativo no systemd, mas policy ${policy_port} ainda não respondeu."
            return 0
        fi
    fi

    if [ "$ready" = false ]; then
        echo -e "${RED}[TIMEOUT]${NC}"
        echo "O serviço demorou a responder na porta ${policy_port}. Verifique: journalctl -u spfbl -f"
        return 1
    fi

    return 0
}

diagnose_spfbl_service() {
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"
    local policy_port="${SPFBL_BACKEND_HTTP_PORT:-9877}"
    echo -e "${YELLOW}[DIAGNÓSTICO]${NC} Coletando informações do serviço SPFBL..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --no-pager status spfbl | tail -n 30 || true
    fi
    ss -lntp 2>/dev/null | grep -E ":(${admin_port}|${policy_port})\\b" || true
    if [ -d /var/log/spfbl ]; then
        tail -n 40 /var/log/spfbl/spfbl.*.log 2>/dev/null || true
    fi
}

verify_installation() {
    local errors=0
    if ! wait_for_port 127.0.0.1 "${SPFBL_FRONT_HTTP_PORT:-9875}" 10; then
        echo -e "${YELLOW}Aviso:${NC} Porta admin ${SPFBL_FRONT_HTTP_PORT:-9875} não respondeu no tempo esperado."
        errors=$((errors + 1))
    fi
    if ! wait_for_port 127.0.0.1 "${SPFBL_BACKEND_HTTP_PORT:-9877}" 10; then
        echo -e "${YELLOW}Aviso:${NC} Porta policy ${SPFBL_BACKEND_HTTP_PORT:-9877} não respondeu no tempo esperado."
        errors=$((errors + 1))
    fi
    if [ "$errors" -gt 0 ]; then
        diagnose_spfbl_service
    fi
}

start_spfbl_service() {
    configure_service
    if ! wait_for_service; then
        diagnose_spfbl_service
        die "SPFBL não respondeu dentro do tempo esperado."
    fi
}

configure_firewall() {
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"
    local policy_port="${SPFBL_BACKEND_HTTP_PORT:-9877}"

    if [ "${FIREWALL_AUTO_CONFIG:-no}" != "yes" ]; then
        echo -e "${YELLOW}[CONFIG]${NC} Firewall automático desativado (FIREWALL_AUTO_CONFIG=${FIREWALL_AUTO_CONFIG:-no})."
        return 0
    fi

    echo -e "${YELLOW}[CONFIG]${NC} Configurando firewall..."

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${web_port}/tcp" >/dev/null 2>&1 || true
        ufw allow "${admin_port}/tcp" >/dev/null 2>&1 || true
        ufw allow "${policy_port}/tcp" >/dev/null 2>&1 || true
        ufw reload >/dev/null 2>&1 || true
        echo -e "${GREEN}Firewall atualizado${NC} (UFW: portas ${web_port}/${admin_port}/${policy_port})."
        return 0
    fi

    echo -e "${YELLOW}Aviso:${NC} UFW não encontrado. Configure o firewall manualmente para ${web_port}/tcp, ${admin_port}/tcp e ${policy_port}/tcp."
    return 0
}

print_final_tests() {
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"
    local policy_port="${SPFBL_BACKEND_HTTP_PORT:-9877}"

    echo "------------------------------------------------"
    if tcp_check 127.0.0.1 "$policy_port"; then
        echo -e "Serviço (${policy_port}):       ${GREEN}ONLINE${NC}"
    else
        echo -e "Serviço (${policy_port}):       ${RED}OFFLINE${NC} (Verifique logs)"
    fi

    if tcp_check 127.0.0.1 "$web_port"; then
        echo -e "Web (${web_port}):           ${GREEN}ONLINE${NC} (http://$REAL_HOSTNAME:${web_port})"
    else
        echo -e "Web (${web_port}):           ${RED}OFFLINE${NC}"
    fi

    if tcp_check 127.0.0.1 "$admin_port"; then
        echo -e "Admin TCP (${admin_port}):   ${GREEN}ONLINE${NC}"
    else
        echo -e "Admin TCP (${admin_port}):   ${RED}OFFLINE${NC}"
    fi

    echo "------------------------------------------------"
    if command -v spfbl >/dev/null 2>&1; then
        echo -e "Comando 'spfbl':      ${GREEN}OK${NC} (/usr/bin/spfbl)"
    else
        echo -e "Comando 'spfbl':      ${RED}ERRO${NC}"
    fi

    echo
    echo "Instalação concluída."
}

configure_store_cron() {
    local cron_job current_cron

    command -v crontab >/dev/null 2>&1 || die "Crontab não encontrado. Instale o pacote 'cron'."

    echo -e "${YELLOW}[CONFIG]${NC} Agendando store diário via crontab..."
    cron_job="0 1 * * * ${SPFBL_BIN%/}/spfbl store"
    current_cron="$(crontab -l 2>/dev/null || true)"

    (printf '%s\n' "$current_cron"; echo "$cron_job") | awk 'NF && !seen[$0]++' | crontab -

    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart cron >/dev/null 2>&1 || true
    else
        /etc/init.d/cron restart >/dev/null 2>&1 || true
    fi

    echo -e "${GREEN}Agendamento validado!${NC} O comando 'spfbl store' executa diariamente às 01:00."
}

configure_locale() {
    echo -e "${YELLOW}[CONFIG]${NC} Configurando localidade para pt_BR..."

    if command -v locale-gen >/dev/null 2>&1; then
        locale-gen "$LOCALE" >/dev/null 2>&1 || true
        locale-gen "$LOCALE.UTF-8" >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure locales >/dev/null 2>&1 || true
    elif command -v localedef >/dev/null 2>&1; then
        localedef -i "$LOCALE" -f UTF-8 "$LOCALE.UTF-8" >/dev/null 2>&1 || true
    fi

    if command -v update-locale >/dev/null 2>&1; then
        update-locale LANG="$LOCALE.UTF-8" >/dev/null 2>&1 || true
    else
        echo "LANG=$LOCALE.UTF-8" > /etc/default/locale
    fi
}

configure_timezone() {
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"
    echo 'Para alterar a timezone do usuário para São Paulo, rode:'
    echo "echo \"USER SET <admin> TIMEZONE America/Sao_Paulo\" | nc localhost ${admin_port}"

    echo "$TIMEZONE" > /etc/timezone
    dpkg-reconfigure --frontend noninteractive tzdata >/dev/null 2>&1 || true
}

configure_chrony() {
    cat <<'EOF' > /etc/chrony/chrony.conf
server a.st1.ntp.br iburst nts
server b.st1.ntp.br iburst nts
server c.st1.ntp.br iburst nts
server d.st1.ntp.br iburst nts
server gps.ntp.br iburst nts

driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
leapsectz right/UTC
EOF

    echo -e "${GREEN}Configuração de NTP concluída!${NC}"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart chrony >/dev/null 2>&1 || true
    else
        service chrony restart >/dev/null 2>&1 || true
    fi

    if command -v chronyc >/dev/null 2>&1; then
        chronyc tracking >/dev/null 2>&1 || true
        echo -e "${GREEN}NTP configurado com sucesso.${NC}"
    else
        echo -e "${YELLOW}Aviso:${NC} 'chronyc' não disponível."
    fi
}

configure_spfbl_admin_account() {
    local admin_port="${SPFBL_FRONT_HTTP_PORT:-9875}"

    [ -n "${SPFBL_ADMIN_EMAIL:-}" ] || {
        echo -e "${YELLOW}Aviso:${NC} SPFBL_ADMIN_EMAIL vazio. Pulando criação de conta admin."
        return 0
    }

    if [ -z "${SPFBL_ADMIN_PASSWORD:-}" ]; then
        if command -v openssl >/dev/null 2>&1; then
            SPFBL_ADMIN_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
        else
            SPFBL_ADMIN_PASSWORD="$(date +%s%N | sha256sum | cut -c1-20)"
        fi
        echo -e "${YELLOW}[CONFIG]${NC} Senha admin gerada automaticamente."
    fi

    if command -v spfbl >/dev/null 2>&1; then
        spfbl user add "$SPFBL_ADMIN_EMAIL" admin >/dev/null 2>&1 || true
    fi

    if command -v nc >/dev/null 2>&1; then
        printf 'USER SET %s PASSWORD %s\n' "$SPFBL_ADMIN_EMAIL" "$SPFBL_ADMIN_PASSWORD" | nc 127.0.0.1 "$admin_port" >/dev/null 2>&1 || {
            echo -e "${YELLOW}Aviso:${NC} Não foi possível definir senha admin via porta ${admin_port}."
        }
    else
        echo -e "${YELLOW}Aviso:${NC} 'nc' não encontrado. Pulei definição de senha admin."
    fi
}

print_admin_dashboard_info() {
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local web_scheme="http"
    local admin_url
    local admin_url_direct

    [ -n "${SPFBL_ADMIN_EMAIL:-}" ] || return 0

    if [ "${SPFBL_HTTP_USE_TLS:-no}" = "yes" ]; then
        web_scheme="https"
        web_port="${SPFBL_WEB_HTTPS_PORT:-443}"
    fi

    admin_url="${web_scheme}://${REAL_HOSTNAME}/${SPFBL_ADMIN_EMAIL}"
    admin_url_direct="${web_scheme}://${REAL_HOSTNAME}:${web_port}/${SPFBL_ADMIN_EMAIL}"

    echo
    echo "Email de admin: ${SPFBL_ADMIN_EMAIL}"
    echo "Senha do admin: ${SPFBL_ADMIN_PASSWORD}"
    echo "URL admin: ${admin_url}"
    if [ "$admin_url_direct" != "$admin_url" ]; then
        echo "URL admin direta: ${admin_url_direct}"
    fi
}

configure_authorized_clients() {
    local registered=0
    local cidr ident contact ip

    if ! command -v spfbl >/dev/null 2>&1; then
        echo -e "${YELLOW}Aviso:${NC} Comando 'spfbl' indisponível. Pulando cadastro de clientes autorizados."
        return 0
    fi

    if [ -n "${SPFBL_CLIENT_CIDR:-}" ]; then
        ident="${SPFBL_CLIENT_LABEL:-$REAL_HOSTNAME}"
        spfbl client add "$SPFBL_CLIENT_CIDR" "$ident" SPFBL "${SPFBL_ADMIN_EMAIL:-}" >/dev/null 2>&1 || true
        registered=$((registered + 1))
    fi

    for entry in "${AUTHORIZED_SERVERS[@]:-}"; do
        [ -n "${entry:-}" ] || continue
        IFS=':' read -r cidr ident contact <<< "$entry"
        [ -n "${cidr:-}" ] || continue
        ident="${ident:-external-client}"
        contact="${contact:-${SPFBL_ADMIN_EMAIL:-}}"
        spfbl client add "$cidr" "$ident" SPFBL "$contact" >/dev/null 2>&1 || true
        registered=$((registered + 1))
    done

    for ip in "${AUTHORIZED_SERVERS_SIMPLE[@]:-}"; do
        [ -n "${ip:-}" ] || continue
        if [[ "$ip" != */* ]]; then
            cidr="${ip}/32"
        else
            cidr="$ip"
        fi
        ident="mail-${cidr//\//_}"
        ident="${ident//./_}"
        spfbl client add "$cidr" "$ident" SPFBL "${SPFBL_ADMIN_EMAIL:-}" >/dev/null 2>&1 || true
        registered=$((registered + 1))
    done

    for entry in "${POLICY_CLIENTS[@]:-}"; do
        [ -n "${entry:-}" ] || continue
        IFS=':' read -r cidr ident contact <<< "$entry"
        [ -n "${cidr:-}" ] || continue
        ident="${ident:-external-client}"
        contact="${contact:-${SPFBL_ADMIN_EMAIL:-}}"
        spfbl client add "$cidr" "$ident" SPFBL "$contact" >/dev/null 2>&1 || true
        registered=$((registered + 1))
    done

    if [ "$registered" -gt 0 ]; then
        echo -e "${GREEN}Clientes autorizados processados:${NC} ${registered}"
    fi
}

setup_directadmin_integration_assets() {
    local web_scheme="http"
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local port_suffix=""
    local base_url public_dir client_src public_client installer_path

    [ "${DIRECTADMIN_INTEGRATION_ENABLE:-yes}" = "yes" ] || {
        echo -e "${YELLOW}[CONFIG]${NC} Integração DirectAdmin desativada (DIRECTADMIN_INTEGRATION_ENABLE=${DIRECTADMIN_INTEGRATION_ENABLE})."
        return 0
    }

    if [ "${SPFBL_HTTP_USE_TLS:-no}" = "yes" ]; then
        web_scheme="https"
        web_port="${SPFBL_WEB_HTTPS_PORT:-443}"
    fi

    if ! { [ "$web_scheme" = "http" ] && [ "$web_port" = "80" ]; } && \
       ! { [ "$web_scheme" = "https" ] && [ "$web_port" = "443" ]; }; then
        port_suffix=":${web_port}"
    fi
    base_url="${web_scheme}://${REAL_HOSTNAME}${port_suffix}"

    public_dir="$INSTALL_DIR/web/public"
    mkdir -p "$public_dir"

    client_src="$REPO_SRC_DIR/client/spfbl.sh"
    if [ ! -f "$client_src" ]; then
        client_src="$SPFBL_BIN/spfbl.sh"
    fi

    public_client="$public_dir/spfbl-client"
    cp -f "$client_src" "$public_client"
    chmod +x "$public_client"
    sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"$REAL_HOSTNAME\"|" "$public_client" || true
    sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"${SPFBL_BACKEND_HTTP_PORT:-9877}\"|" "$public_client" || true
    sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"${SPFBL_FRONT_HTTP_PORT:-9875}\"|" "$public_client" || true

    installer_path="$public_dir/install-directadmin.sh"
    cat > "$installer_path" <<EOF
#!/bin/bash
set -euo pipefail

SPFBL_HOST="${REAL_HOSTNAME}"
SPFBL_POLICY_PORT="${SPFBL_BACKEND_HTTP_PORT:-9877}"
SPFBL_ADMIN_PORT="${SPFBL_FRONT_HTTP_PORT:-9875}"
BASE_URL="${base_url}"
CACHE_BUSTER="\$(date +%s)"
CLIENT_REGISTER_EMAIL="${DIRECTADMIN_CLIENT_EMAIL:-}"

echo -e "
                                                           
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄   ▄▄▄                  
█████▀▀▀ ███▀▀███▄ ███▀▀▀▀▀ ███▀▀███▄ ███             ██   
 ▀████▄  ███▄▄███▀ ███▄▄    ███▄▄███▀ ███      ▄█▀█▄ ▀██▀▀ 
   ▀████ ███▀▀▀▀   ███▀▀    ███  ███▄ ███      ██▄█▀  ██   
███████▀ ███       ███      ████████▀ ████████ ▀█▄▄▄  ██   
                                                           

Versão: 1.0 (beta)      
Node: Child - Versão DirectAdmin
Hostname: $REAL_HOSTNAME                                                                                     
"

log() { printf '[%s] %s\n' "\$(date +'%Y-%m-%d %H:%M:%S')" "\$*"; }

detect_my_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="\$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [ -z "\$ip" ]; then
    ip="\$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i==\"src\"){print \$(i+1); exit}}}')"
  fi
  echo "\$ip"
}

[[ \$EUID -eq 0 ]] || { echo "Execute como root"; exit 1; }
[[ -f /usr/local/directadmin/directadmin ]] || { echo "DirectAdmin não detectado"; exit 1; }

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y curl wget netcat-openbsd >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl wget nmap-ncat >/dev/null 2>&1 || true
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/spfbl-client?v=\${CACHE_BUSTER}" -o /usr/local/bin/spfbl
else
  wget -qO /usr/local/bin/spfbl "\${BASE_URL}/public/spfbl-client?v=\${CACHE_BUSTER}"
fi

chmod +x /usr/local/bin/spfbl
sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"\${SPFBL_HOST}\"|" /usr/local/bin/spfbl
sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"\${SPFBL_POLICY_PORT}\"|" /usr/local/bin/spfbl
sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"\${SPFBL_ADMIN_PORT}\"|" /usr/local/bin/spfbl

MY_IP="\$(detect_my_ip)"
MY_HOST="\$(hostname -f 2>/dev/null || hostname)"
MY_EMAIL="\${CLIENT_REGISTER_EMAIL:-auto@\${MY_HOST}}"

if command -v nc >/dev/null 2>&1; then
  RESP="\$(printf 'CLIENT ADD %s/32 %s SPFBL %s\n' "\$MY_IP" "\$MY_HOST" "\$MY_EMAIL" | nc -w 2 "\$SPFBL_HOST" "\$SPFBL_ADMIN_PORT" 2>/dev/null || true)"
  if echo "\$RESP" | grep -Eq 'ADDED|ALREADY'; then
    log "Cliente registrado no SPFBL: \$MY_IP (\$MY_HOST)"
  else
    log "Auto-registro não confirmou. Rode manualmente no servidor SPFBL:"
    log "spfbl client add \$MY_IP/32 \$MY_HOST SPFBL \$MY_EMAIL"
  fi
fi

if [ -f /etc/exim.acl_check_recipient.pre.conf ]; then
  cp -a /etc/exim.acl_check_recipient.pre.conf "/etc/exim.acl_check_recipient.pre.conf.bak.\$(date +%Y%m%d%H%M%S)"
fi

cat > /etc/exim.acl_check_recipient.pre.conf <<'EOFRCP'
warn
  set acl_m_spfbl = \${run{/usr/local/bin/spfbl query \\
    \$sender_host_address \\
    \$sender_address \\
    \$sender_helo_name \\
    \$local_part@\$domain}{\$value}{TIMEOUT}}

warn
  log_message = SPFBL-CHECK: \$acl_m_spfbl

deny
  condition = \${if match{\$acl_m_spfbl}{^(BLOCKED|BANNED)}{yes}{no}}
  message = Message rejected by SPFBL security policy

accept
  condition = \${if match{\$acl_m_spfbl}{^WHITE}{yes}{no}}
EOFRCP

log "Integração aplicada. No DirectAdmin, execute:"
log "cd /usr/local/directadmin/custombuild && ./build rewrite_confs && ./build exim_conf"
log "systemctl restart exim"
EOF
    chmod +x "$installer_path"

    echo
    echo -e "${GREEN}Integração remota pronta.${NC}"
    echo "Cliente SPFBL: ${base_url}/public/spfbl-client"
    echo "One-liner DirectAdmin:"
    echo "curl -sSL '${base_url}/public/install-directadmin.sh?v=\$(date +%s)' | sudo bash"
}

setup_cpanel_integration_assets() {
    local web_scheme="http"
    local web_port="${SPFBL_WEB_HTTP_PORT:-80}"
    local port_suffix=""
    local base_url public_dir cpanel_src firewall_src cpanel_dst firewall_dst installer_path
    local child_installer_version="${CHILD_CPANEL_INSTALLER_VERSION:-1.1.0}"
    local child_installer_generated_at
    local cpanel_acl_recipient cpanel_acl_dkim cpanel_acl_message

    [ "${CPANEL_INTEGRATION_ENABLE:-yes}" = "yes" ] || {
        echo -e "${YELLOW}[CONFIG]${NC} Integração cPanel desativada (CPANEL_INTEGRATION_ENABLE=${CPANEL_INTEGRATION_ENABLE})."
        return 0
    }

    if [ "${SPFBL_HTTP_USE_TLS:-no}" = "yes" ]; then
        web_scheme="https"
        web_port="${SPFBL_WEB_HTTPS_PORT:-443}"
    fi

    if ! { [ "$web_scheme" = "http" ] && [ "$web_port" = "80" ]; } && \
       ! { [ "$web_scheme" = "https" ] && [ "$web_port" = "443" ]; }; then
        port_suffix=":${web_port}"
    fi
    base_url="${web_scheme}://${REAL_HOSTNAME}${port_suffix}"
    child_installer_generated_at="$(date +'%Y-%m-%d %H:%M:%S %z')"
    public_dir="$INSTALL_DIR/web/public"
    mkdir -p "$public_dir"

    cpanel_src="$REPO_SRC_DIR/client/spfbl.cpanel.sh"
    firewall_src="$REPO_SRC_DIR/client/firewall.cpanel.sh"
    cpanel_acl_recipient="$REPO_SRC_DIR/client/spfbl_end_recipient"
    cpanel_acl_dkim="$REPO_SRC_DIR/client/spfbl_begin_smtp_dkim"
    cpanel_acl_message="$REPO_SRC_DIR/client/spfbl_begin_check_message_pre"
    cpanel_dst="$public_dir/spfbl.cpanel.sh"
    firewall_dst="$public_dir/firewall.cpanel.sh"

    if [ ! -f "$cpanel_src" ]; then
        echo -e "${YELLOW}Aviso:${NC} Script base cPanel não encontrado em $cpanel_src. Pulando assets cPanel."
        return 0
    fi

    cp -f "$cpanel_src" "$cpanel_dst"
    chmod +x "$cpanel_dst"
    sed -i "s|54\\.233\\.253\\.229|${REAL_HOSTNAME}|g" "$cpanel_dst" || true
    sed -i "s|9877|${SPFBL_BACKEND_HTTP_PORT:-9877}|g" "$cpanel_dst" || true

    if [ -f "$firewall_src" ]; then
        cp -f "$firewall_src" "$firewall_dst"
        chmod +x "$firewall_dst"
        sed -i "s|54\\.233\\.253\\.229|${REAL_HOSTNAME}|g" "$firewall_dst" || true
        sed -i "s|9877|${SPFBL_BACKEND_HTTP_PORT:-9877}|g" "$firewall_dst" || true
    fi

    # Publica arquivos ACL para instalação cPanel sem dependência da matrix.
    [ -f "$cpanel_acl_recipient" ] && cp -f "$cpanel_acl_recipient" "$public_dir/spfbl_end_recipient"
    [ -f "$cpanel_acl_dkim" ] && cp -f "$cpanel_acl_dkim" "$public_dir/spfbl_begin_smtp_dkim"
    [ -f "$cpanel_acl_message" ] && cp -f "$cpanel_acl_message" "$public_dir/spfbl_begin_check_message_pre"

    # Garante publicação do cliente SPFBL para cPanel também.
    if [ ! -f "$public_dir/spfbl-client" ]; then
        cp -f "$REPO_SRC_DIR/client/spfbl.sh" "$public_dir/spfbl-client"
        chmod +x "$public_dir/spfbl-client"
    fi
    sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"$REAL_HOSTNAME\"|" "$public_dir/spfbl-client" || true
    sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"${SPFBL_BACKEND_HTTP_PORT:-9877}\"|" "$public_dir/spfbl-client" || true
    sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"${SPFBL_FRONT_HTTP_PORT:-9875}\"|" "$public_dir/spfbl-client" || true

    installer_path="$public_dir/install-child-cpanel.sh"
    cat > "$installer_path" <<EOF
#!/bin/bash
set -euo pipefail

BASE_URL="${base_url}"
SPFBL_ADMIN_HOST="${REAL_HOSTNAME}"
SPFBL_ADMIN_PORT="${SPFBL_FRONT_HTTP_PORT:-9875}"
SPFBL_POLICY_PORT="${SPFBL_BACKEND_HTTP_PORT:-9877}"
SPFBL_DASHBOARD_EMAIL="${SPFBL_ADMIN_EMAIL:-postmaster@domain.com}"
CLIENT_REGISTER_EMAIL="${DIRECTADMIN_CLIENT_EMAIL:-}"
CACHE_BUSTER="\$(date +%s)"
BACKUP_ROOT="/root/spfbl_backups_spfbl"
LOG_FILE="/var/log/spfbl-cpanel-installer.log"
CHILD_HOSTNAME="\$(hostname -f 2>/dev/null || hostname)"
MASTER_IP=""
INSTALLER_VERSION="${child_installer_version}"
INSTALLER_GENERATED_AT="${child_installer_generated_at}"

echo -e "
                                                           
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄   ▄▄▄                  
█████▀▀▀ ███▀▀███▄ ███▀▀▀▀▀ ███▀▀███▄ ███             ██   
 ▀████▄  ███▄▄███▀ ███▄▄    ███▄▄███▀ ███      ▄█▀█▄ ▀██▀▀ 
   ▀████ ███▀▀▀▀   ███▀▀    ███  ███▄ ███      ██▄█▀  ██   
███████▀ ███       ███      ████████▀ ████████ ▀█▄▄▄  ██   
                                                           

Versão: 1.0 (beta)      
Node: Child - Versão cPanel
Hostname: $REAL_HOSTNAME                                                                                     
"

echo "Instalador SPFBL (child) para cPanel - versão \${INSTALLER_VERSION}"
echo "Build: \${INSTALLER_GENERATED_AT}"

log() {
  local msg="[\$(date +'%Y-%m-%d %H:%M:%S')] \$*"
  echo "\$msg"
  echo "\$msg" >> "\$LOG_FILE"
}

detect_my_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="\$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [ -z "\$ip" ]; then
    ip="\$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i==\"src\"){print \$(i+1); exit}}}')"
  fi
  echo "\$ip"
}

resolve_master_ip() {
  if command -v getent >/dev/null 2>&1; then
    MASTER_IP="\$(getent ahostsv4 "\$SPFBL_ADMIN_HOST" | awk '/STREAM/{print \$1; exit}')"
  fi
  if [ -z "\$MASTER_IP" ] && command -v dig >/dev/null 2>&1; then
    MASTER_IP="\$(dig +short A "\$SPFBL_ADMIN_HOST" | head -n1)"
  fi
  if [ -z "\$MASTER_IP" ] && command -v host >/dev/null 2>&1; then
    MASTER_IP="\$(host "\$SPFBL_ADMIN_HOST" 2>/dev/null | awk '/has address/{print \$NF; exit}')"
  fi
}

[[ \$EUID -eq 0 ]] || { echo "Execute como root"; exit 1; }
[[ -x /usr/local/cpanel/cpanel ]] || { echo "cPanel não detectado"; exit 1; }

backup_if_exists() {
  local f="\$1"
  if [ -e "\$f" ]; then
    mkdir -p "\$(dirname "\$BACKUP_SET_DIR\$f")"
    cp -a "\$f" "\$BACKUP_SET_DIR\$f"
  else
    echo "\$f" >> "\$BACKUP_SET_DIR/.absent_files"
  fi
}

restore_if_exists() {
  local f="\$1"
  if [ -e "\$LAST_BACKUP_SET\$f" ]; then
    mkdir -p "\$(dirname "\$f")"
    cp -a "\$LAST_BACKUP_SET\$f" "\$f"
    log "Restaurado: \$f"
  elif [ -f "\$LAST_BACKUP_SET/.absent_files" ] && grep -Fxq "\$f" "\$LAST_BACKUP_SET/.absent_files"; then
    rm -f "\$f"
    log "Removido (não existia antes): \$f"
  else
    log "Sem backup para: \$f"
  fi
}

run_post_install_tests() {
  local check_output query_output ticket_url

  log "Iniciando testes pós-instalação com SPFBL master..."

  if ! command -v nc >/dev/null 2>&1; then
    log "Teste 1/2 e 2/2 ignorados: comando 'nc' não encontrado."
    return 0
  fi

  if ! command -v /usr/local/bin/spfbl >/dev/null 2>&1; then
    log "Teste 2/2 ignorado: /usr/local/bin/spfbl não encontrado."
    return 0
  fi

  log "Teste 1/2: CHECK (esperado: SOFTFAIL sem ticket URL)"
  check_output="\$(echo "CHECK 8.8.8.8 teste@gmail.com gmail.com \${SPFBL_DASHBOARD_EMAIL}" | nc -w 8 "\${SPFBL_ADMIN_HOST}" "\${SPFBL_POLICY_PORT}" 2>/dev/null || true)"
  if echo "\$check_output" | grep -qi "SOFTFAIL"; then
    if echo "\$check_output" | grep -Eqi "https?://"; then
      log "Resultado 1/2: recebeu SOFTFAIL com URL (aceitável)."
    else
      log "Resultado 1/2: SOFTFAIL sem ticket URL (OK)."
    fi
  else
    log "Resultado 1/2: não retornou SOFTFAIL. Saída:"
    echo "\$check_output"
  fi

  log "Teste 2/2: QUERY (esperado: SOFTFAIL com ticket URL)"
  query_output="\$(/usr/local/bin/spfbl query 8.8.8.8 teste@gmail.com gmail.com "\${SPFBL_DASHBOARD_EMAIL}" 2>&1 || true)"
  ticket_url="\$(echo "\$query_output" | grep -Eo 'https?://[^ ]+' | head -n1 || true)"
  if echo "\$query_output" | grep -qi "SOFTFAIL" && [ -n "\$ticket_url" ]; then
    log "Resultado 2/2: SOFTFAIL com ticket (OK)."
    log "Ticket gerado: \$ticket_url"
  else
    log "Resultado 2/2: não confirmou ticket. Saída:"
    echo "\$query_output"
  fi
}

run_debug_menu() {
  local option check_output query_output ticket_url rcpt

  touch "\$LOG_FILE"
  resolve_master_ip

  while true; do
    echo
    echo "=== SPFBL Debug Menu ==="
    echo "Master: \${SPFBL_ADMIN_HOST} (\${MASTER_IP:-IP não resolvido})"
    echo "Child:  \${CHILD_HOSTNAME}"
    echo "1) Executar teste de rota para servidor master"
    echo "2) Verificar conectividade (local e remota)"
    echo "3) Simular SOFTFAIL com hostname do servidor filho"
    echo "4) Simular ticket no master (query com URL)"
    echo "5) Simular SPAM no master (envio SMTP local + query)"
    echo "0) Sair"
    read -r -p "Escolha uma opção: " option

    case "\$option" in
      1)
        log "DEBUG 1: rota para master"
        ip route get "\${MASTER_IP:-8.8.8.8}" 2>/dev/null || true
        ;;
      2)
        log "DEBUG 2: conectividade"
        nc -vz "\$SPFBL_ADMIN_HOST" "\$SPFBL_POLICY_PORT" 2>/dev/null || true
        nc -vz "\$SPFBL_ADMIN_HOST" "\$SPFBL_ADMIN_PORT" 2>/dev/null || true
        nc -vz 127.0.0.1 25 2>/dev/null || true
        ;;
      3)
        log "DEBUG 3: simulação SOFTFAIL (CHECK)"
        check_output="\$(echo "CHECK 8.8.8.8 teste@gmail.com \${CHILD_HOSTNAME} \${SPFBL_DASHBOARD_EMAIL}" | nc -w 8 "\$SPFBL_ADMIN_HOST" "\$SPFBL_POLICY_PORT" 2>/dev/null || true)"
        echo "\$check_output"
        ;;
      4)
        log "DEBUG 4: simulação ticket (QUERY)"
        query_output="\$(/usr/local/bin/spfbl query 8.8.8.8 teste@gmail.com \${CHILD_HOSTNAME} "\${SPFBL_DASHBOARD_EMAIL}" 2>&1 || true)"
        ticket_url="\$(echo "\$query_output" | grep -Eo 'https?://[^ ]+' | head -n1 || true)"
        echo "\$query_output"
        [ -n "\$ticket_url" ] && echo "Ticket: \$ticket_url"
        ;;
      5)
        log "DEBUG 5: simulação SPAM"
        rcpt="\${SPFBL_DASHBOARD_EMAIL}"
        if command -v swaks >/dev/null 2>&1; then
          swaks --server 127.0.0.1 --port 25 --helo "\$CHILD_HOSTNAME" \
            --from spammer@bad-domain.test --to "\$rcpt" \
            --header "Subject: VIAGRA CASINO FREE CRYPTO" \
            --body "buy now bonus winner free" || true
        else
          echo "swaks não encontrado, pulando envio SMTP local."
        fi
        query_output="\$(/usr/local/bin/spfbl query 185.220.101.1 spammer@bad-domain.test "\${CHILD_HOSTNAME}" "\$rcpt" 2>&1 || true)"
        echo "\$query_output"
        ticket_url="\$(echo "\$query_output" | grep -Eo 'https?://[^ ]+' | head -n1 || true)"
        [ -n "\$ticket_url" ] && echo "Ticket: \$ticket_url"
        ;;
      0) break ;;
      *) echo "Opção inválida." ;;
    esac
  done
}

run_install() {
  BACKUP_TS="\$(date +%Y%m%d_%H%M%S)"
  BACKUP_SET_DIR="\$BACKUP_ROOT/\$BACKUP_TS"
  mkdir -p "\$BACKUP_SET_DIR"
  touch "\$LOG_FILE"

  backup_if_exists /etc/exim.conf.local
  backup_if_exists /etc/exim.conf.localopts
  backup_if_exists /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
  backup_if_exists /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
  backup_if_exists /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
  backup_if_exists /usr/local/bin/spfbl
  backup_if_exists /usr/local/bin/spfbl.cpanel.sh
  backup_if_exists /usr/local/bin/spfbl-firewall-update
  log "Backup salvo em: \$BACKUP_SET_DIR"

  mkdir -p /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK
  mkdir -p /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK
  mkdir -p /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/spfbl-client?v=\${CACHE_BUSTER}" -o /usr/local/bin/spfbl
    curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/spfbl_end_recipient?v=\${CACHE_BUSTER}" -o /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
    curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/spfbl_begin_smtp_dkim?v=\${CACHE_BUSTER}" -o /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
    curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/spfbl_begin_check_message_pre?v=\${CACHE_BUSTER}" -o /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
    curl -fsSL -H 'Cache-Control: no-cache' "\${BASE_URL}/public/firewall.cpanel.sh?v=\${CACHE_BUSTER}" -o /usr/local/bin/spfbl-firewall-update || true
  else
    wget -qO /usr/local/bin/spfbl "\${BASE_URL}/public/spfbl-client?v=\${CACHE_BUSTER}"
    wget -qO /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient "\${BASE_URL}/public/spfbl_end_recipient?v=\${CACHE_BUSTER}"
    wget -qO /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim "\${BASE_URL}/public/spfbl_begin_smtp_dkim?v=\${CACHE_BUSTER}"
    wget -qO /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre "\${BASE_URL}/public/spfbl_begin_check_message_pre?v=\${CACHE_BUSTER}"
    wget -qO /usr/local/bin/spfbl-firewall-update "\${BASE_URL}/public/firewall.cpanel.sh?v=\${CACHE_BUSTER}" || true
  fi
  chmod +x /usr/local/bin/spfbl
  chmod +x /usr/local/bin/spfbl-firewall-update 2>/dev/null || true

  if ! grep -q '^spamd_address = ' /etc/exim.conf.local 2>/dev/null; then
    echo "spamd_address = ${REAL_HOSTNAME} ${SPFBL_BACKEND_HTTP_PORT:-9877} retry=30s tmo=3m" >> /etc/exim.conf.local
  else
    sed -i "s|^spamd_address = .*|spamd_address = ${REAL_HOSTNAME} ${SPFBL_BACKEND_HTTP_PORT:-9877} retry=30s tmo=3m|" /etc/exim.conf.local
  fi

  if ! grep -q '^timeout_frozen_after = ' /etc/exim.conf.local 2>/dev/null; then
    echo "timeout_frozen_after = 7d" >> /etc/exim.conf.local
  fi

  if ! grep -q '^smtp_accept_max = ' /etc/exim.conf.local 2>/dev/null; then
    echo "smtp_accept_max = 250" >> /etc/exim.conf.local
  fi

  exim_opt_set() {
    local option_name="\$1"
    local option_value="\$2"
    touch /etc/exim.conf.localopts
    if grep -q "^\\\${option_name}=" /etc/exim.conf.localopts; then
      sed -i "s/^\\\${option_name}=.*/\\\${option_name}=\\\${option_value}/" /etc/exim.conf.localopts
    else
      echo "\\\${option_name}=\\\${option_value}" >> /etc/exim.conf.localopts
    fi
  }

  exim_opt_set "spfbl_end_recipient" "1"
  exim_opt_set "spfbl_begin_smtp_dkim" "1"
  exim_opt_set "spfbl_begin_check_message_pre" "1"
  exim_opt_set "acl_delay_unknown_hosts" "0"
  exim_opt_set "acl_dkim_disable" "0"
  exim_opt_set "acl_dkim_bl" "0"
  exim_opt_set "acl_spam_scan_secondarymx" "0"
  exim_opt_set "acl_outgoing_spam_scan" "0"
  exim_opt_set "acl_outgoing_spam_scan_over_int" "0"
  exim_opt_set "acl_default_exiscan" "0"
  exim_opt_set "acl_default_spam_scan" "0"
  exim_opt_set "acl_default_spam_scan_check" "0"
  exim_opt_set "acl_slow_fail_block" "0"

  /usr/local/cpanel/scripts/buildeximconf >/dev/null 2>&1 || true
  /usr/local/cpanel/scripts/restartsrv_exim >/dev/null 2>&1 || true
  /usr/local/bin/spfbl-firewall-update >/dev/null 2>&1 || true

  MY_IP="\$(detect_my_ip)"
  MY_HOST="\$(hostname -f 2>/dev/null || hostname)"
  MY_EMAIL="\${CLIENT_REGISTER_EMAIL:-auto@\${MY_HOST}}"
  if command -v nc >/dev/null 2>&1; then
    RESP="\$(printf 'CLIENT ADD %s/32 %s SPFBL %s\n' "\$MY_IP" "\$MY_HOST" "\$MY_EMAIL" | nc -w 2 "\$SPFBL_ADMIN_HOST" "\$SPFBL_ADMIN_PORT" 2>/dev/null || true)"
    if echo "\$RESP" | grep -Eq 'ADDED|ALREADY'; then
      log "Cliente registrado no SPFBL: \$MY_IP (\$MY_HOST)"
    else
      log "Auto-registro não confirmou. Rode manualmente no SPFBL:"
      log "spfbl client add \$MY_IP/32 \$MY_HOST SPFBL \$MY_EMAIL"
    fi
  fi

  run_post_install_tests
  log "Integração cPanel concluída."
}

run_restore() {
  touch "\$LOG_FILE"
  if [ ! -d "\$BACKUP_ROOT" ]; then
    log "Nenhum backup encontrado em \$BACKUP_ROOT"
    exit 1
  fi

  LAST_BACKUP_SET="\$(ls -1dt "\$BACKUP_ROOT"/* 2>/dev/null | head -n1 || true)"
  if [ -z "\$LAST_BACKUP_SET" ] || [ ! -d "\$LAST_BACKUP_SET" ]; then
    log "Nenhum conjunto de backup disponível para restauração."
    exit 1
  fi

  log "Restaurando último backup: \$LAST_BACKUP_SET"
  restore_if_exists /etc/exim.conf.local
  restore_if_exists /etc/exim.conf.localopts
  restore_if_exists /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
  restore_if_exists /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
  restore_if_exists /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
  restore_if_exists /usr/local/bin/spfbl
  restore_if_exists /usr/local/bin/spfbl.cpanel.sh
  restore_if_exists /usr/local/bin/spfbl-firewall-update

  # Fallback agressivo: se não houver backup suficiente, limpa traços SPFBL e
  # retorna para o padrão do MTA local.
  sed -i '/^spfbl_end_recipient=/d;/^spfbl_begin_smtp_dkim=/d;/^spfbl_begin_check_message_pre=/d' /etc/exim.conf.localopts 2>/dev/null || true
  sed -i '/^spamd_address = /d' /etc/exim.conf.local 2>/dev/null || true
  rm -f /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
  rm -f /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
  rm -f /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre

  /usr/local/cpanel/scripts/buildeximconf >/dev/null 2>&1 || true
  /usr/local/cpanel/scripts/restartsrv_exim >/dev/null 2>&1 || true
  log "Restauração concluída (modo padrão MTA sem SPFBL)."
}

case "\${1:---install}" in
  --install) run_install ;;
  --restore) run_restore ;;
  --debug) run_debug_menu ;;
  --version)
    echo "install-child-cpanel.sh versão \${INSTALLER_VERSION}"
    echo "build \${INSTALLER_GENERATED_AT}"
    ;;
  *)
    echo "Uso: \$0 [--install|--restore|--debug|--version]"
    exit 1
    ;;
esac
EOF
    chmod +x "$installer_path"

    echo "One-liner cPanel (child/client):"
    echo "curl -sSL '${base_url}/public/install-child-cpanel.sh?v=\$(date +%s)' | sudo bash"
}

run_autowhitelist_setup() {
    local spfbl_server_ip autowh_script
    local rc=0

    if [ "${SPFBL_AUTOWHITELIST_ENABLE:-yes}" != "yes" ]; then
        echo -e "${YELLOW}[CONFIG]${NC} Automação de whitelist desativada (SPFBL_AUTOWHITELIST_ENABLE=${SPFBL_AUTOWHITELIST_ENABLE})."
        return 0
    fi

    echo "Detectando seu MTA e gerando script de configuração para facilitar..."

    spfbl_server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$spfbl_server_ip" ] || spfbl_server_ip="127.0.0.1"

    export SPFBL_CLIENT_BIN="/usr/bin/spfbl"
    export SPFBL_SERVER_HOSTNAME="$REAL_HOSTNAME"
    export SPFBL_SERVER_IP="$spfbl_server_ip"
    export SPFBL_POLICY_PORT="${SPFBL_BACKEND_HTTP_PORT:-9877}"
    export SPFBL_ADMIN_PORT="${SPFBL_FRONT_HTTP_PORT:-9875}"
    export WHITELIST_CRON_SCHEDULE
    export SPFBL_AUTOWHITELIST_NONINTERACTIVE=1

    autowh_script="$SCRIPT_DIR/spfbl_client_autowhitelist.sh"
    if [ -x "$autowh_script" ]; then
        "$autowh_script" || rc=$?
    elif [ -f "$autowh_script" ]; then
        chmod +x "$autowh_script"
        "$autowh_script" || rc=$?
    else
        echo -e "${YELLOW}Aviso:${NC} Script de whitelist não encontrado em $autowh_script"
        return 0
    fi

    if [ "$rc" -ne 0 ]; then
        if [ "${SPFBL_AUTOWHITELIST_REQUIRED:-no}" = "yes" ]; then
            die "Falha ao executar automação de whitelist (exit=${rc})."
        fi
        echo -e "${YELLOW}Aviso:${NC} Automação de whitelist falhou (exit=${rc}), mas a instalação vai continuar."
    fi
}

main() {
    require_root
    prepare_logs

    echo -e "${GREEN}=== Iniciando Instalador SPFBL ===${NC}"
    detect_network
    detect_public_ip

    validate_memory_config
    resolve_and_validate_hostname

    echo -e "Diretório de Instalação: ${YELLOW}$INSTALL_DIR${NC}"

    banner
    install_dependencies
    configure_exim4
    ensure_java
    install_spfbl_files
    configure_self_signed_tls
    configure_files
    configure_cli
    start_spfbl_service
    print_final_tests
    verify_installation
    configure_firewall
    configure_spfbl_admin_account
    configure_authorized_clients
    setup_directadmin_integration_assets
    setup_cpanel_integration_assets
    print_admin_dashboard_info
    configure_store_cron
    configure_locale
    configure_timezone
    configure_chrony
    run_autowhitelist_setup

    echo -e "${GREEN}Instalação e Configuração Completa!${NC}"
}

main "$@"
