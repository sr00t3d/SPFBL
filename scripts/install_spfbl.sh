#!/bin/bash

# ==============================================================================
# Instalador SPFBL
# Documentação em:
# Refazendo o processo de instalação do SPFBL, com melhorias significativas para garantir uma instalação mais robusta, amigável e compatível com diferentes sistemas Linux. O script agora inclui:
# - Detecção automática do sistema de init (Systemd ou Init.d) e configuração adequada
# - Verificação e instalação automática do Java, com fallback para download manual se necessário
# - Configuração de logs detalhados para facilitar a depuração em caso de falhas
# - Spinner visual para indicar o progresso das etapas de instalação
# - Configuração automática do hostname e URL no arquivo de configuração do SPFBL
# - Criação de um wrapper global para o comando 'spfbl' para facilitar o acesso
# - Agendamento automático do comando 'spfbl store' via crontab para backups diários
# - Configuração de localidade e timezone para pt_BR e America/Sao_Paulo
# - Configuração do serviço de NTP (Chrony) para manter o relógio do sistema sincronizado, o que é crucial para o funcionamento correto do SPFBL e para evitar problemas relacionados a timestamps e expiração de tokens.
# ==============================================================================

# Definição do diretório base de instalação e arquivos de log

# Diretorio de instalação do SPFBL
INSTALL_DIR="/opt/spfbl"

# Arquivos de log para monitorar a instalação e os comandos executados
LOG_FILE="/var/log/spfbl_install.log"

# Arquivo de log específico para os comandos executados durante a instalação, para facilitar a depuração em caso de falhas
CMD_LOG="/var/log/spfbl_cmd.log"

# Diretorio para o comando spfbl.sh, que é o wrapper do cliente CLI, para facilitar o acesso global ao comando sem precisar do caminho completo
# Você pod mover para qualquer outro diretorio o wrapper vai apontar para o script original na pasta de instalação, mas o ideal é deixar em /usr/local/bin para seguir as convenções do sistema e evitar conflitos com outros comandos
SPFBL_BIN="/usr/local/bin/"

# Diretorio temporário para a instalação, onde os arquivos serão baixados e preparados antes de serem movidos para o diretório final de instalação. Isso ajuda a manter o processo organizado e evita que arquivos temporários sejam misturados com os arquivos finais.
TEMP_SPFBLDIR="/tmp/spfbl_inst"

# Configurações de Localidade e Timezone
LOCALE="pt_BR"
TIMEZONE="America/Sao_Paulo"

# Configurações desejadas (Pode manter o 'm' aqui, o script limpa abaixo)
JAVA_MIN_HEAP="128m"
JAVA_MAX_HEAP="512m"

# Extrai apenas os números para fins de cálculo/comparação
MIN_VAL=$(echo $JAVA_MIN_HEAP | sed 's/[^0-9]//g')
MAX_VAL=$(echo $JAVA_MAX_HEAP | sed 's/[^0-9]//g')

# Obtém a memória disponível real
AVAILABLE_MEM=$(free -m | awk '/^Mem:/{print $7}')

# VALIDAÇÃO CRÍTICA: O sistema tem o mínimo que eu exijo?
if [ "$AVAILABLE_MEM" -lt "$MIN_VAL" ]; then
    echo -e "${RED}ERRO FATAL: Memória disponível (${AVAILABLE_MEM}MB) é menor que o mínimo exigido (${JAVA_MIN_HEAP}).${NC}"
    echo -e "${RED}O serviço SPFBL não será iniciado para evitar instabilidade extrema.${NC}"
    exit 1
fi

# VALIDAÇÃO DE SEGURANÇA: O máximo definido cabe na RAM?
if [ "$MAX_VAL" -gt "$AVAILABLE_MEM" ]; then
    echo -e "${YELLOW}AVISO: JAVA_MAX_HEAP (${JAVA_MAX_HEAP}) excede a RAM disponível (${AVAILABLE_MEM}MB).${NC}"
    
    # Aqui decidimos: Se o sistema tem o MIN, mas não tem o MAX, 
    # nós ajustamos o MAX para o limite da máquina em vez de dar exit.
    JAVA_MAX_HEAP="${AVAILABLE_MEM}m"
    echo -e "${YELLOW}Ajustando JAVA_MAX_HEAP para o limite real de ${JAVA_MAX_HEAP}.${NC}"
fi

# GARANTIA FINAL: Min nunca maior que Max
# (Útil caso o ajuste do passo 2 tenha jogado o Max para baixo do Min original)
MAX_VAL_ADJUSTED=$(echo $JAVA_MAX_HEAP | sed 's/[^0-9]//g')
if [ "$MIN_VAL" -gt "$MAX_VAL_ADJUSTED" ]; then
    JAVA_MIN_HEAP=$JAVA_MAX_HEAP
fi

echo -e "${GREEN}Configuração validada: Min=${JAVA_MIN_HEAP} / Max=${JAVA_MAX_HEAP}${NC}"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Função de Log
log_msg() {
    local TYPE=$1
    local MSG=$2
    echo "[$TYPE]: $MSG" >> "$LOG_FILE"
}

# Função de Erro Fatal
die() {
    echo -e "${RED}[ERRO FATAL]${NC} $1"
    log_msg "!" "ERRO: $1"
    if [ -f "$CMD_LOG" ]; then 
        echo -e "${YELLOW}--- Log do Erro ---${NC}"
        tail -n 10 "$CMD_LOG" 
    fi
    exit 1
}

# Valida hostname conforme regras básicas RFC (labels 1-63, total <=253)
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

# Spinner Visual
exec_visual() {
    local msg="$1"; shift
    echo -ne "${YELLOW}[PROCESSANDO]${NC} $msg ... "
    "$@" > "$CMD_LOG" 2>&1 &
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    wait $pid
    local exit_code=$?
    printf "    \b\b\b\b"
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC}"
    else
        echo -e "${RED}[FALHA]${NC}"
        return $exit_code
    fi
}

# --- INÍCIO ---

if [ "$EUID" -ne 0 ]; then echo -e "${RED}Execute como root.${NC}"; exit 1; fi

# Limpa logs anteriores
rm -f "$CMD_LOG"
touch "$LOG_FILE"

echo -e "${GREEN}=== Iniciando Instalador SPFBL ===${NC}"
echo -e "Diretório de Instalação: ${YELLOW}$INSTALL_DIR${NC}"

# 1. Dependências e Java
exec_visual "Atualizando apt" apt-get update
exec_visual "Instalando dependencias" apt-get install wget git ncat nmap procps default-jre chrony cron -y

# Garante Java
if ! command -v java &> /dev/null; then
    exec_visual "Tentando Java Manual via APT" apt-get install default-jre -y
    
    # Se falhar o apt, tenta manualmente baixando a JDK do site oficial (Ajustado para JDK 17, que é a versão mínima recomendada)
    if ! command -v java &> /dev/null; then
        echo -e "${YELLOW}Java via APT falhou/inexistente. Tentando manual...${NC}"
        cd /opt || die "Sem acesso a /opt"
        
        exec_visual "Baixando JDK 17 (Pode demorar)" wget -q https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz
        
        exec_visual "Extraindo JDK" tar -zxf openjdk-17.0.2_linux-x64_bin.tar.gz -C /usr/lib/jvm/ 2>/dev/null || { mkdir -p /usr/lib/jvm && tar -zxf openjdk-17.0.2_linux-x64_bin.tar.gz -C /usr/lib/jvm/; }
        
        # Link simbólico
        if [ -f "/usr/lib/jvm/jdk-17.0.2/bin/java" ]; then
            ln -sf /usr/lib/jvm/jdk-17.0.2/bin/java /usr/bin/java
        fi
    fi
fi

# Verifica Java final e pega o caminho
JAVA_PATH=$(readlink -f $(which java))
if [ -z "$JAVA_PATH" ]; then die "Java não encontrado."; fi

# 2. Instalação Arquivos
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p $TEMP_SPFBLDIR
    cd $TEMP_SPFBLDIR
    exec_visual "Baixando SPFBL" git clone https://github.com/leonamp/SPFBL/ .
    
    mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/history" /var/log/spfbl
    
    # Move arquivos principais para a nova pasta
    mv dist/SPFBL.jar run/spfbl.conf lib/ data/ web/ template/ "$INSTALL_DIR/"
    
    # Copia scripts originais para a pasta de instalação
    cp run/spfbl-init.sh "/etc/init.d/spfbl-init.sh"

    # Ajustando memoria no init script para refletir as variáveis de configuração
    sed -i "s|/usr/bin/java|$JAVA_PATH|g" "/etc/init.d/spfbl-init.sh"
    sed -i "s/java -jar/java -Xms$JAVA_MIN_HEAP -Xmx$JAVA_MAX_HEAP -jar/g" "/etc/init.d/spfbl-init.sh"

    cp client/spfbl.sh "$SPFBL_BIN/spfbl.sh"
    
    cd /root
fi

chmod +x "/etc/init.d/spfbl-init.sh"

# 3. FIX HOSTNAME (Evita o erro de HTTP socket not binded)
echo -e "${YELLOW}[CONFIG]${NC} Ajustando Hostname e URL..."
REAL_HOSTNAME=$(hostname -f 2>/dev/null)
if [ -z "$REAL_HOSTNAME" ] || [ "$REAL_HOSTNAME" = "(none)" ]; then
    REAL_HOSTNAME=$(hostname)
fi

if ! is_valid_hostname "$REAL_HOSTNAME"; then
    die "Hostname inválido: '$REAL_HOSTNAME'. Configure um hostname válido (ex.: mail.seudominio.com) e rode novamente."
    exit 0
fi

if [ -f "$INSTALL_DIR/spfbl.conf" ]; then
    sed -i "s/^hostname=.*/hostname=$REAL_HOSTNAME/" "$INSTALL_DIR/spfbl.conf"
    sed -i "s|^url=.*|url=http://$REAL_HOSTNAME:9875/|" "$INSTALL_DIR/spfbl.conf"
fi

# 4. Configura Cliente CLI (Ajustado para wrapper global)
echo -e "${YELLOW}[CONFIG]${NC} Configurando CLI (/usr/bin/spfbl)..."

# Ajusta o IP interno do cliente para localhost no arquivo original
sed -i "s/54.233.253.229/127.0.0.1/g" "$SPFBL_BIN/spfbl.sh"

# O ncat (do projeto Nmap) tenta gerenciar a conexão de forma mais rígida. Se ele não recebe um EOF (fim de arquivo) exatamente como espera logo após o echo, ele assume que a conexão "morreu" ou deu timeout, ignorando o que o Java enviou de volta. O nc (netcat-openbsd) é mais "burro" e simplesmente despeja o que recebe no terminal, por isso funciona, se você estiver tendo problemas de conexão altere abaixo para nc, mas lembre-se que o ncat tem mais recursos e pode ser mais seguro em alguns casos, então use com cautela. O ideal é usar o ncat, mas se ele não funcionar, o nc é uma alternativa viável.

# https://www.baeldung.com/linux/netcat-vs-nc-vs-ncat

# sed -i "s/ncat/nc/g" "$SPFBL_BIN/spfbl.sh"

# Cria o wrapper em /usr/bin que chama o script na pasta correta
# O .sh permanece no bin porém usamos aqui o wrapper para chamar no sistema sem precisar do caminho completo
cat <<EOF > /usr/bin/spfbl
#!/bin/bash
/bin/bash $SPFBL_BIN/spfbl.sh "\$@"
EOF
chmod +x /usr/bin/spfbl

# 5. CONFIGURAÇÃO DO SERVIÇO (SYSTEMD + FALLBACK)
echo -e "${YELLOW}[CONFIG]${NC} Configurando Serviço..."

# Mata processos antigos para evitar conflito
pkill -f SPFBL.jar >/dev/null 2>&1

# Verifica se Systemd está rodando DE FATO
USE_SYSTEMD=false
if command -v systemctl &> /dev/null && pidof systemd &> /dev/null; then
    USE_SYSTEMD=true
fi

if [ "$USE_SYSTEMD" = true ]; then
    echo -e "   -> Sistema detectado: ${GREEN}Systemd${NC}"
    
    # Cria o arquivo de serviço apontando para $INSTALL_DIR e limitando memória
    # Obs: Issues no spbl.service do repo oficial
    # https://github.com/leonamp/SPFBL/issues/101

    cat <<EOF > /etc/systemd/system/spfbl.service
[Unit]
Description=SPFBL Service
After=network.target syslog.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$JAVA_PATH -Xms$JAVA_MIN_HEAP -Xmx$JAVA_MAX_HEAP -jar $INSTALL_DIR/SPFBL.jar
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

    # Executa comandos do systemd protegidos
    exec_visual "Recarregando Daemon" systemctl daemon-reload
    
    # Se falhar o reload, muda a flag para usar init.d
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Falha no reload do Systemd. Tentando fallback para Init.d...${NC}"
        USE_SYSTEMD=false
    else
        exec_visual "Habilitando Serviço" systemctl enable spfbl
        exec_visual "Iniciando SPFBL (Systemd)" systemctl start spfbl
    fi
fi

# Se não tiver Systemd OU se o Systemd falhou acima (FALLBACK COMPLETO)
if [ "$USE_SYSTEMD" = false ]; then
    echo -e "   -> Sistema detectado: ${YELLOW}Init.d / SysVinit${NC}"
    
    ln -sf "$INSTALL_DIR/spfbl-init.sh" /etc/init.d/spfbl
    chmod 755 /etc/init.d/spfbl
    
    # Tenta registrar o serviço
    if command -v update-rc.d &> /dev/null; then
        update-rc.d spfbl defaults >/dev/null 2>&1
    elif command -v chkconfig &> /dev/null; then
        chkconfig --add spfbl >/dev/null 2>&1
    fi

    exec_visual "Iniciando SPFBL (Init.d)" /etc/init.d/spfbl start
fi

# 6. Aguarda e Testa (Loop Inteligente)
echo -ne "${YELLOW}[AGUARDANDO]${NC} Inicializando JVM e Banco de Dados... "

# Loop de 20 segundos checando a porta
READY=false
for i in {1..20}; do
    if nc -zv 127.0.0.1 9877 >/dev/null 2>&1; then
        READY=true
        echo -e "${GREEN}[PRONTO]${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

if [ "$READY" = false ]; then
    echo -e "${RED}[TIMEOUT]${NC}"
    echo "O serviço demorou a responder, mas pode estar subindo. Verifique: tail -f /var/log/syslog"
fi

# Testes Finais
echo "------------------------------------------------"
# Teste Local Serviço
if nc -zv 127.0.0.1 9877 > /dev/null 2>&1; then
    echo -e "Serviço (9877):       ${GREEN}ONLINE${NC}"
else
    echo -e "Serviço (9877):       ${RED}OFFLINE${NC} (Verifique logs)"
fi

# Teste Local Admin
if nc -zv 127.0.0.1 9875 > /dev/null 2>&1; then
    echo -e "Admin (9875):         ${GREEN}ONLINE${NC} (http://$REAL_HOSTNAME:9875)"
else
    echo -e "Admin (9875):         ${RED}OFFLINE${NC}"
fi

# Teste do comando CLI
echo "------------------------------------------------"
if command -v spfbl > /dev/null; then
    echo -e "Comando 'spfbl':      ${GREEN}OK${NC} (/usr/bin/spfbl)"
else
    echo -e "Comando 'spfbl':      ${RED}ERRO${NC}"
fi

echo ""
echo "Instalação concluída."

# Verifica se o executável crontab existe no sistema
if command -v crontab >/dev/null 2>&1; then
    echo -e "${YELLOW}[CONFIG]${NC} Agendando store diário via crontab..."
    
    # 1. Lista o crontab atual
    # 2. Filtra para não duplicar a linha se o script for rodado duas vezes (grep -v)
    # 3. Adiciona a nova linha sem o campo "root"
    (crontab -l 2>/dev/null | grep -v "$SPFBL_BIN/spfbl.sh store"; echo "0 1 * * * $SPFBL_BIN/spfbl store") | crontab -
    /etc/init.d/cron restart
    echo -e "${GREEN}Agendamento criado com sucesso!${NC} O comando 'spfbl store' será executado diariamente às 01:00."
else
    die "Crontab não encontrado. Instale o pacote 'cron' para agendar backups automáticos."
fi

# Configurndo pais e idioma para pt_BR
echo -e "${YELLOW}[CONFIG]${NC} Configurando localidade para pt_BR..."
sudo locale-gen $LOCALE
sudo locale-gen $LOCALE.UTF-8
sudo dpkg-reconfigure locales
sudo update-locale LANG=$LOCALE.UTF-8

echo "Para alterar a timezone do usuário para São Paulo, basta rodar esse comando:
echo "USER SET <admin> TIMEZONE America/Sao_Paulo" | nc localhost 9875"

# Configura o timezone para America/Sao_Paulo
echo "$TIMEZONE" > /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata

# Configurando ntp para manter o relógio atualizado

cat <<EOF > /etc/chrony/chrony.conf
# servidores publicos do NTP.br com NTS disponível
server a.st1.ntp.br iburst nts
server b.st1.ntp.br iburst nts
server c.st1.ntp.br iburst nts
server d.st1.ntp.br iburst nts
server gps.ntp.br iburst nts

# caso deseje pode configurar servidores adicionais com NTS, como os da cloudflare e netnod
# nesse caso basta descomentar as linhas a seguir
# server time.cloudflare.com iburst nts
# server nts.netnod.se iburst nts

# arquivo usado para manter a informação do atraso do seu relógio local
driftfile /var/lib/chrony/chrony.drift

# local para as chaves e cookies NTS
ntsdumpdir /var/lib/chrony

# se quiser um log detalhado descomente as linhas a seguir
#log tracking measurements statistics
#logdir /var/log/chrony

# erro máximo tolerado em ppm em relação aos servidores
maxupdateskew 100.0

# habilita a sincronização via kernel do real-time clock a cada 11 minutos
rtcsync

# ajusta a hora do sistema com um "salto", de uma só vez, ao invés de
# ajustá-la aos poucos corrigindo a frequência, mas isso apenas se o erro
# for maior do que 1 segundo e somente para os 3 primeiros ajustes
makestep 1 3

# diretiva que indica que o offset UTC e leapseconds devem ser lidos
# da base tz (de time zone) do sistema
leapsectz right/UTC
EOF

echo -e "${GREEN}Configuração de NTP concluída!${NC} O serviço Chrony foi configurado para usar servidores NTP públicos com suporte a NTS, garantindo que o relógio do sistema esteja sempre preciso."

service chrony restart

echo "Verificando o nível de sincronização do relógio..."

if chronyc -v java &> /dev/null; then
    chronyc tracking && chronyc sources && chronyc -N authdata
    echo -e "${GREEN}NTP configurado com sucesso.${NC}"
else
    echo -e "${YELLOW}Aviso:${NC} O comando 'chronyc' não está disponível ou não pode ser executado. Verifique a instalação do Chrony para garantir que o relógio do sistema esteja sincronizado."
fi

# Gerando scrpt de configuração
echo "Detectando seu MTA e gerando script de configuração para facilitar..."

cd $TEMP_SPFBLDIR/scripts/ &&
./spfbl_client_autowhitelist.sh

#rm -rf $TEMP_SPFBLDIR

#echo -e "${GREEN}Instalação e Configuração Completa!${NC} O SPFBL está instalado, o serviço configurado, o comando 'spfbl' disponível globalmente, e o sistema preparado para manter o relógio sincronizado. Verifique os logs para detalhes adicionais."