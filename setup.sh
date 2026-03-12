#!/usr/bin/env bash
set -e

# site-manager setup script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.site-manager"

echo "==> Verificando Python 3.10+..."
python_version=$(python3 -c 'import sys; print(sys.version_info >= (3, 10))')
if [ "$python_version" != "True" ]; then
    echo "ERRO: Python 3.10+ é necessário."
    exit 1
fi
echo "    OK: $(python3 --version)"

echo ""
echo "==> Instalando dependências Python..."
pip3 install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "==> Criando diretório de configuração em $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"

echo ""
echo "==> Verificando ferramentas de firewall..."
if command -v ufw &>/dev/null; then
    echo "    OK: ufw encontrado (método padrão)"
elif command -v iptables &>/dev/null; then
    echo "    OK: iptables encontrado (use --block-method iptables)"
else
    echo "    AVISO: ufw e iptables não encontrados. Use --block-method nginx."
fi

echo ""
echo "==> Verificando nginx..."
if command -v nginx &>/dev/null; then
    echo "    OK: nginx encontrado"
    # Cria arquivo de IPs bloqueados se não existir
    BLOCKED_CONF="/etc/nginx/conf.d/blocked-ips.conf"
    if [ ! -f "$BLOCKED_CONF" ]; then
        echo "    Criando $BLOCKED_CONF..."
        echo "# IPs bloqueados pelo site-manager" | sudo tee "$BLOCKED_CONF" > /dev/null
        echo "    ATENÇÃO: Adicione 'include /etc/nginx/conf.d/blocked-ips.conf;' dentro do bloco http{} do seu nginx.conf se ainda não estiver lá."
    fi
else
    echo "    AVISO: nginx não encontrado no PATH"
fi

echo ""
echo "==> Download do banco de dados GeoLite2 (MaxMind)..."
if [ -z "$MAXMIND_LICENSE_KEY" ]; then
    echo "    AVISO: Variável MAXMIND_LICENSE_KEY não definida."
    echo "    Para usar GeoIP offline (mais rápido, sem limite de requisições):"
    echo "    1. Crie uma conta gratuita em https://www.maxmind.com/en/geolite2/signup"
    echo "    2. Gere uma license key em Account > Manage License Keys"
    echo "    3. Execute: MAXMIND_LICENSE_KEY=suachave bash setup.sh"
    echo ""
    echo "    Sem o banco GeoLite2, o app usará ip-api.com (fallback, 45 req/min)."
else
    echo "    Baixando GeoLite2-City.mmdb..."
    DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    TMPFILE=$(mktemp /tmp/geolite2_XXXXXX.tar.gz)
    if curl -sL -o "$TMPFILE" "$DOWNLOAD_URL"; then
        tar -xzf "$TMPFILE" -C "$CONFIG_DIR" --wildcards "*.mmdb" --strip-components=1 2>/dev/null || \
        tar -xzf "$TMPFILE" -C "$CONFIG_DIR" --wildcards "*/*.mmdb" --transform 's|.*/||' 2>/dev/null
        rm -f "$TMPFILE"
        if [ -f "$CONFIG_DIR/GeoLite2-City.mmdb" ]; then
            echo "    OK: GeoLite2-City.mmdb salvo em $CONFIG_DIR/"
        else
            echo "    ERRO: Falha ao extrair .mmdb. Verifique a license key."
        fi
    else
        echo "    ERRO: Falha no download. Verifique a license key e conexão."
        rm -f "$TMPFILE"
    fi
fi

echo ""
echo "==> Setup concluído!"
echo ""
echo "    Para iniciar o monitoramento:"
echo "    python3 $SCRIPT_DIR/main.py --log-file /var/log/nginx/access.log"
echo ""
echo "    Opções disponíveis:"
echo "    --log-file PATH        Caminho do log do nginx (padrão: /var/log/nginx/access.log)"
echo "    --geoip-db PATH        Caminho do GeoLite2-City.mmdb (padrão: ~/.site-manager/GeoLite2-City.mmdb)"
echo "    --block-method METHOD  Método de bloqueio: ufw, iptables, nginx (padrão: ufw)"
echo "    --rate-threshold N     Requisições/min para marcar como bot (padrão: 100)"
echo "    --refresh N            Intervalo de atualização em segundos (padrão: 1.0)"
echo "    --demo                 Modo demo com dados simulados (para testar sem log real)"
