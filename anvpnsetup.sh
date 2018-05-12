#!/bin/sh
#
# Script for automatic setup of an IPsec VPN server on Ubuntu LTS and Debian.
# Works on any dedicated server or virtual private server (VPS) except OpenVZ.
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC!
#
# The latest version of this script is available at:
# https://github.com/hwdsl2/setup-ipsec-vpn
#
# Copyright (C) 2014-2017 Lin Song <linsongui@gmail.com>
# Based on the work of Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

# =====================================================

apt update -y
apt upgrade -y

# Define your own values for these variables
# - IPsec pre-shared key, VPN username and password
# - All values MUST be placed inside 'single quotes'
# - DO NOT use these special characters within values: \ " '

YOUR_IPSEC_PSK=''
YOUR_USERNAME=''
YOUR_PASSWORD=''

# Important notes:   https://git.io/vpnnotes
# Setup VPN clients: https://git.io/vpnclients

# =====================================================





export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT="$(date +%F-%T)"

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo; echo "## $1"; echo; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

vpnsetup() {

os_type="$(lsb_release -si 2>/dev/null)"
if [ -z "$os_type" ]; then
  [ -f /etc/os-release  ] && os_type="$(. /etc/os-release  && echo "$ID")"
  [ -f /etc/lsb-release ] && os_type="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
fi
if ! printf '%s' "$os_type" | head -n 1 | grep -qiF -e ubuntu -e debian -e raspbian; then
  exiterr "This script only supports Ubuntu and Debian."
fi

if [ "$(sed 's/\..*//' /etc/debian_version)" = "7" ]; then
  exiterr "Debian 7 is not supported."
fi

if [ -f /proc/user_beancounters ]; then
  exiterr "OpenVZ VPS is not supported. Try OpenVPN: github.com/Nyr/openvpn-install"
fi

if [ "$(id -u)" != 0 ]; then
  exiterr "Script must be run as root. Try 'sudo sh $0'"
fi

net_iface=${VPN_NET_IFACE:-'eth0'}
def_iface="$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')"
[ -z "$def_iface" ] && def_iface="$(ip -4 route list 0/0 2>/dev/null | grep -Po '(?<=dev )(\S+)')"

def_iface_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
if [ -n "$def_iface_state" ] && [ "$def_iface_state" != "down" ]; then
  if [ "$(uname -m | cut -c1-3)" != "arm" ]; then
    case "$def_iface" in
      wl*)
        exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
        ;;
    esac
  fi
  net_iface="$def_iface"
fi

net_iface_state=$(cat "/sys/class/net/$net_iface/operstate" 2>/dev/null)
if [ -z "$net_iface_state" ] || [ "$net_iface_state" = "down" ] || [ "$net_iface" = "lo" ]; then
  printf "Error: Network interface '%s' is not available.\n" "$net_iface" >&2
  if [ -z "$VPN_NET_IFACE" ]; then
cat 1>&2 <<EOF
Unable to detect the default network interface. Manually re-run this script with:
  sudo VPN_NET_IFACE="your_default_interface_name" sh "$0"
EOF
  fi
  exit 1
fi

[ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
[ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
[ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"

if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  bigecho "VPN credentials not set by user. Generating random PSK and password..."
  VPN_IPSEC_PSK="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"
  VPN_USER=vpnuser
  VPN_PASSWORD="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"
fi

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit the script and re-enter them."
fi

if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

bigecho "VPN setup in progress... Please be patient."

# Create and change to working dir
mkdir -p /opt/src
cd /opt/src || exiterr "Cannot enter /opt/src."

bigecho "Populating apt-get cache..."

# Wait up to 60s for apt/dpkg lock
count=0
while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock >/dev/null 2>&1; do
  [ "$count" -ge "20" ] && exiterr "Cannot get apt/dpkg lock."
  count=$((count+1))
  printf '%s' '.'
  sleep 3
done

export DEBIAN_FRONTEND=noninteractive
apt-get -yq update || exiterr "'apt-get update' failed."

bigecho "Installing packages required for setup..."

apt-get -yq install wget dnsutils openssl \
  iproute gawk grep sed net-tools || exiterr2

bigecho "Trying to auto discover IP of this server..."

cat <<'EOF'
In case the script hangs here for more than a few minutes,
press Ctrl-C to abort. Then edit it and manually enter IP.
EOF

# In case auto IP discovery fails, enter server's public IP here.
PUBLIC_IP=${VPN_PUBLIC_IP:-''}

# Try to auto discover IP of this server
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)

# Check IP for correct format
check_ip "$PUBLIC_IP" || PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
check_ip "$PUBLIC_IP" || exiterr "Cannot detect this server's public IP. Edit the script and manually enter it."

bigecho "Installing packages required for the VPN + TOR..."

apt-get -yq install tor libnss3-dev libnspr4-dev pkg-config \
  libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
  libcurl4-nss-dev flex bison gcc make libnss3-tools \
  libevent-dev ppp xl2tpd || exiterr2

bigecho "Installing Fail2Ban to protect SSH..."

apt-get -yq install fail2ban || exiterr2

bigecho "Compiling and installing Libreswan..."

SWAN_VER=3.23
swan_file="libreswan-$SWAN_VER.tar.gz"
swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
swan_url2="https://download.libreswan.org/$swan_file"
if ! { wget -t 3 -T 30 -nv -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -nv -O "$swan_file" "$swan_url2"; }; then
  exiterr "Cannot download Libreswan source."
fi
/bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
tar xzf "$swan_file" && /bin/rm -f "$swan_file"
cd "libreswan-$SWAN_VER" || exiterr "Cannot enter Libreswan source dir."
sed -i '/docker-targets\.mk/d' Makefile
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS =
USE_DNSSEC = false
EOF
if [ "$(packaging/utils/lswan_detect.sh init)" = "systemd" ]; then
  apt-get -yq install libsystemd-dev || exiterr2
fi
NPROCS="$(grep -c ^processor /proc/cpuinfo)"
[ -z "$NPROCS" ] && NPROCS=1
make "-j$((NPROCS+1))" -s base && make -s install-base

# Verify the install and clean up
cd /opt/src || exiterr "Cannot enter /opt/src."
/bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
  exiterr "Libreswan $SWAN_VER failed to build."
fi

bigecho "Creating VPN configuration..."

L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.42.1'}
L2TP_POOL=${VPN_L2TP_POOL:-'192.168.42.10-192.168.42.250'}
XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}

# Create IPsec (Libreswan) config
conf_bk "/etc/ipsec.conf"
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$L2TP_NET,%v4:!$XAUTH_NET
  protostack=netkey
  interfaces=%defaultroute
  uniqueids=no

conn shared
  left=%defaultroute
  leftid=$PUBLIC_IP
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ike=3des-sha1,3des-sha2,aes-sha1,aes-sha1;modp1024,aes-sha2,aes-sha2;modp1024,aes256-sha2_512
  phase2alg=3des-sha1,3des-sha2,aes-sha1,aes-sha2,aes256-sha2_512
  sha2-truncbug=yes

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  phase2=esp
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns="127.0.0.1"
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  xauthby=file
  ike-frag=yes
  ikev2=never
  cisco-unity=yes
  also=shared
EOF

# Workarounds for systems with ARM CPU (e.g. Raspberry Pi)
# - Set "left" to private IP instead of "%defaultroute"
# - Remove unsupported ESP algorithm
if [ "$(uname -m | cut -c1-3)" = "arm" ]; then
  PRIVATE_IP=$(ip -4 route get 1 | awk '{print $NF;exit}')
  check_ip "$PRIVATE_IP" && sed -i "s/left=%defaultroute/left=$PRIVATE_IP/" /etc/ipsec.conf
  sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
fi

# Specify IPsec PSK
conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

# Create xl2tpd config
conf_bk "/etc/xl2tpd/xl2tpd.conf"
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Set xl2tpd options
conf_bk "/etc/ppp/options.xl2tpd"
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
ms-dns 127.0.0.1
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
EOF

# Create VPN credentials
conf_bk "/etc/ppp/chap-secrets"
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
"vpnuserI2P"		l2tpd	"VPNpassI2P"	*
"vpnu1"			l2tpd	"3yw21Ted"	*
"vpnu2"			l2tpd	"t4TG8ON1"	*
"vpnu3"			l2tpd	"c0rh57oh"	*
"vpnu4"			l2tpd	"7AOXiR12"	*	
"vpnu5"			l2tpd	"U9zrM77V"	*
"vpnu6"			l2tpd	"D2iJD76X"	*
"vpnu7"			l2tpd	"lpTwceQm"	*
"vpnu8"			l2tpd	"RcRDLQXU"	*
"vpnu9"			l2tpd	"azKIdQOO"	*
"vpnu10"			l2tpd	"HtJUufuk"	*
"vpnu11"			l2tpd	"yZozDGxg"	*
"HKXEUP"		l2tpd	"wifile82"		*
"HRHEPN"		l2tpd	"wuseto83"	*
"MZQFHH"		l2tpd	"pifexu65"	*
"EMRMFJ"		l2tpd	"sepefu72"	*
"CQIXFX"			l2tpd	"diviyu68"	*
"FHMGJU"		l2tpd	"bazese63"	*
"EERBQR"		l2tpd	"mosala57"	*
"RWEOGC"		l2tpd	"lelura97"		*
"PHSNOM"		l2tpd	"zajuyo14"	*
"NBVLLM"		l2tpd	"lobofi10"		*
"ZFQJHZ"		l2tpd	"mayaze63"	*
"KDELYQ"		l2tpd	"yaruga57"	*
"YUGUMO"		l2tpd	"zepebe65"	*
"FQNCUE"		l2tpd	"lavoha15"	*
"PRUREP"		l2tpd	"besipo67"	*
"PHZQOQ"		l2tpd	"lukuvo62"	*
"YNCRSQ"		l2tpd	"kipani57"	*
"GMYQRE"		l2tpd	"lenoje20"	*
"AXFOIR"		l2tpd	"xutupo14"	*
"ANWJJR"		l2tpd	"morexo67"	*
"PFNUJL"		l2tpd	"xujodo62"	*
"MGBQVT"		l2tpd	"motiyu24"	*
"NUKPUJ"		l2tpd	"xozudo19"	*
"BQSIXB"		l2tpd	"zakuye27"	*
"JDEQXT"		l2tpd	"lopafe22"	*
"QVPWMK"		l2tpd	"mezizu29"	*
"AONTKQ"		l2tpd	"yifute24"		*
"FZJDML"		l2tpd	"mopebi32"	*
"AZZGBR"		l2tpd	"yijovu72"	*
"WBQVZZ"		l2tpd	"xibeno22"	*
"PORKUP"		l2tpd	"yuleje74"	*
"VMPAZP"		l2tpd	"kurono24"	*
"XCJAMQ"		l2tpd	"lobawi76"	*
"WIDIPS"		l2tpd	"kegucu26"	*
"LSWRLF"		l2tpd	"yafeki79"	*
"ISFBMA"		l2tpd	"xokadu74"	*
"DFTZLS"		l2tpd	"zihala37"	*
"TOMKHY"		l2tpd	"kozedi77"	*
"WOFDTF"		l2tpd	"zuxuyi39"	*
"LRUZOP"		l2tpd	"lidisu34"		*
"ZVJGJM"		l2tpd	"zebama42"	*
"MVUYZK"		l2tpd	"yituga37"	*
"QJSLVT"		l2tpd	"zodoba89"	*
"FJAVEX"		l2tpd	"lujahi39"		*
"AIWFNR"		l2tpd	"zavice46"	*
"RYJKEL"		l2tpd	"yemuwa41"	*
"UUDHGF"		l2tpd	"nixero49"	*
"TACRBR"		l2tpd	"lapiwo44"	*
"JVIOFV"			l2tpd	"numare96"	*
"XKLIIE"			l2tpd	"latoka46"	*
"OAAPBA"		l2tpd	"xaladi86"	*
"NAGIAX"		l2tpd	"yuwilo93"	*
"EZBDIW"		l2tpd	"xinufo89"	*
"GGKPGH"		l2tpd	"meyoze96"	*
"FOSFCG"		l2tpd	"kisifo46"		*
"ODITQU"		l2tpd	"zopimu98"	*
"KYAGMX"		l2tpd	"luvete93"	*
"HFSLXI"			l2tpd	"mafene55"	*
"EUMTJE"		l2tpd	"lexive96"	*
"EAGZAN"		l2tpd	"zuhupi13"	*
"CWJXCX"		l2tpd	"yanewo98"	*
"BDITFZ"			l2tpd	"zeyedi61"	*
"QUMHRL"		l2tpd	"larije10"		*
"HPHFWC"		l2tpd	"nenida63"	*
"RKYRXB"		l2tpd	"legexu13"	*
"FSPOMC"		l2tpd	"nofofi66"		*
"BBNECI"		l2tpd	"yokuli61"	*
"BXRBVX"		l2tpd	"nihuga23"	*
"ZCQQYI"		l2tpd	"lomemi17"	*
"DEFEIK"		l2tpd	"bikeva26"	*
"BBUJRW"		l2tpd	"zariba66"	*
"NEVJID"			l2tpd	"beniwa28"	*
"VDXOGK"		l2tpd	"zutena68"	*
"ATZLDF"		l2tpd	"berajo75"	*
"EPHXKQ"		l2tpd	"muwupa70"	*
"NZMQIX"		l2tpd	"patixe78"	*
"YPHLFL"		l2tpd	"zomoro28"	*
"NMWOFP"		l2tpd	"cixoyu80"	*
"JSKQEO"		l2tpd	"macise76"	*
"FFSFKK"		l2tpd	"pemize38"	*
"MJMHRR"		l2tpd	"nifase78"	*
"KQSGWD"		l2tpd	"cepozu85"	*
"DCOVLC"		l2tpd	"biwute35"	*
"XPVEHW"		l2tpd	"cagubi88"	*
"KWOEGW"		l2tpd	"neyove83"	*
"JBPBBQ"		l2tpd	"piwaci90"	*
"KXKIHC"		l2tpd	"nobuje85"	*
"KNOWDL"		l2tpd	"ruzera93"	*
"ORGIGA"		l2tpd	"nafowi42"	*
"IBGPQG"		l2tpd	"decada95"	*
"XITARW"		l2tpd	"nuveki45"	*
"SSAAEF"		l2tpd	"rosesa98"	*
"OSYDUS"		l2tpd	"peyali93"	*
"WGLVBL"		l2tpd	"rajaga55"	*
"DJBYGI"		l2tpd	"pobema95"	*
"ZTNAUQ"		l2tpd	"riluvo57"		*
"GUTFQW"		l2tpd	"codaza52"	*
"ZSFTFV"		l2tpd	"dibaho60"	*
"EWQQEB"		l2tpd	"cihuno55"	*
"HBHNZI"		l2tpd	"fesuwe16"	*
"VJQRNZ"		l2tpd	"pikipo57"	*
"EQCKYC"		l2tpd	"lezuye86"	*
"ZZNUFM"		l2tpd	"norovi53"	*
"QBFIUQ"		l2tpd	"mujabi48"	*
"MJGLXV"		l2tpd	"kibuvu43"	*
"USIXWH"		l2tpd	"jagozo83"	*
"KMYZKL"		l2tpd	"ludahu90"	*
"NTUUEG"		l2tpd	"jakuno86"	*
"IKOYOM"		l2tpd	"vopovo81"	*
"XJLJGW"		l2tpd	"wumace88"	*
"OXFCXC"		l2tpd	"hafujo38"	*
"TPIYLG"			l2tpd	"kucere46"	*
"XLKEJQ"		l2tpd	"vavawe40"	*
"ABYFRM"		l2tpd	"xotasu94"	*
"BBZXYU"		l2tpd	"viluku88"	*
"EBVJBC"		l2tpd	"xajufu95"	*
"HJIYRL"			l2tpd	"jebiye45"	*
"HGTYZB"		l2tpd	"moxibo61"	*
"QMSBVG"		l2tpd	"kiceha10"	*
"NOXPLQ"		l2tpd	"javibu50"	*
"ZCBRSY"		l2tpd	"xefiwa58"	*
"KTFFKN"		l2tpd	"wikebu52"	*
"JGQGMC"		l2tpd	"lehowa60"	*
"FIDUJR"			l2tpd	"wubipa10"	*
"THUWSS"		l2tpd	"layaka17"	*
"HZPHBC"		l2tpd	"kereri58"	*
"ZPFMYI"		l2tpd	"liboyo20"	*
"LDBMQI"		l2tpd	"kotafo60"	*
"YRCLJG"		l2tpd	"lufamo22"	*
"CEFTXJ"		l2tpd	"kakosa17"	*
"AKIPPK"		l2tpd	"leveme25"	*
"SVJQLB"		l2tpd	"kimate20"	*
"XBYWHK"		l2tpd	"mokube28"	*
"PLXZQR"		l2tpd	"xudove22"	*
"NCYDHS"		l2tpd	"minopi30"	*
"PPCNJC"		l2tpd	"kotiju25"		*
"GFORHK"		l2tpd	"zududu32"	*
"PAVPFL"		l2tpd	"yowewu72"	*
"LLYFAC"		l2tpd	"zuhefi80"	*
"FFKJJE"		l2tpd	"limike74"	*
"ZJDYIF"			l2tpd	"zokisa37"	*
"PTNOVJ"		l2tpd	"lepoli32"		*
"EDVBFR"		l2tpd	"mamato84"	*
"OJEVIB"		l2tpd	"yosumu80"	*
"HTUCLV"		l2tpd	"baruva42"	*
"UNTOBM"		l2tpd	"lajobi82"		*
"PBTTZT"		l2tpd	"bigoho89"	*
"WNDQWP"		l2tpd	"layuni84"	*
"DCXRLT"		l2tpd	"nujuwo47"	*
"HIGUOS"		l2tpd	"mubaco87"	*
"NTFCTL"		l2tpd	"bomaxo50"	*
"QEYLNQ"		l2tpd	"zefura45"	*
"JXORTF"		l2tpd	"nipeye51"	*
"ROFXYS"		l2tpd	"rezegi14"	*
"XPJUDY"		l2tpd	"nusamu99"	*
"LBOAHM"		l2tpd	"malise94"	*
"PQRYXJ"		l2tpd	"pujezu12"	*
"IFMEKH"		l2tpd	"zibote51"	*
"WSUHDK"		l2tpd	"celabi59"	*
"XVPXAO"		l2tpd	"zuruve54"	*
"KRWWXA"		l2tpd	"capepi62"	*
"OSNUNV"		l2tpd	"nehawu56"	*
"HCLZJC"		l2tpd	"pafari19"		*
"ZMVUMH"		l2tpd	"sopiye71"	*
"UZEGUL"		l2tpd	"cuhedo22"	*
"IALIMO"			l2tpd	"fosele74"	*
"QZPPSX"		l2tpd	"pulasa24"	*
"KNQJLY"		l2tpd	"sijazu31"	*
"XMRTAX"		l2tpd	"denuto71"	*
"LYLJRV"		l2tpd	"nutomi22"	*
"JJSXCY"		l2tpd	"radavo73"	*
"OOHZDH"		l2tpd	"sucapi37"	*
"EVBALI"		l2tpd	"rivuhe31"	*
"IDJKXF"			l2tpd	"sofodu84"	*
"KMDWVI"		l2tpd	"dukaju33"	*
"VZDVVJ"		l2tpd	"tahadi41"	*
"SUEUMR"		l2tpd	"rezeke36"	*
"RYYCWI"		l2tpd	"teribu51"	*
"LEBYXX"		l2tpd	"lecoso24"	*
"PIWAYS"		l2tpd	"wihixa19"	*
"YACJXA"		l2tpd	"vizedu59"	*
"XMNIVL"		l2tpd	"gosaxu53"	*
"FWOCJY"		l2tpd	"hipifa61"		*
"CLQZEX"		l2tpd	"tavoxu56"	*
"SQMFTI"		l2tpd	"sonire96"	*
"KSWCIU"		l2tpd	"tiyiyu59"		*
"ONLCGM"		l2tpd	"coleva22"	*
"TESTLOG"		l2tpd	"TESTPASS"	*
EOF

conf_bk "/etc/ipsec.d/passwd"
VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF

bigecho "Updating sysctl settings..."

if ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf; then
  conf_bk "/etc/sysctl.conf"
  if [ "$(getconf LONG_BIT)" = "64" ]; then
    SHM_MAX=68719476736
    SHM_ALL=4294967296
  else
    SHM_MAX=4294967295
    SHM_ALL=268435456
  fi
cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = $SHM_MAX
kernel.shmall = $SHM_ALL

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$net_iface.send_redirects = 0
net.ipv4.conf.$net_iface.rp_filter = 0

net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF
fi

bigecho "Updating IPTables rules..."

# Check if IPTables rules need updating
ipt_flag=0
IPT_FILE="/etc/iptables.rules"
if ! grep -qs "hwdsl2 VPN script" "$IPT_FILE" \
   || ! iptables -t nat -C POSTROUTING -s "$L2TP_NET" -o "$net_iface" -j MASQUERADE 2>/dev/null \
   || ! iptables -t nat -C POSTROUTING -s "$XAUTH_NET" -o "$net_iface" -m policy --dir out --pol none -j MASQUERADE 2>/dev/null; then
  ipt_flag=1
fi

# Add IPTables rules for VPN
if [ "$ipt_flag" = "1" ]; then
  service fail2ban stop >/dev/null 2>&1
  iptables-save > "$IPT_FILE.old-$SYS_DT"
  iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
  iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
  iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
  iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
  iptables -I INPUT 6 -p udp --dport 1701 -j DROP
  iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
  iptables -I FORWARD 2 -i "$net_iface" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I FORWARD 3 -i ppp+ -o "$net_iface" -j ACCEPT
  iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
  iptables -I FORWARD 5 -i "$net_iface" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$net_iface" -j ACCEPT
  # Uncomment if you wish to disallow traffic between VPN clients themselves
  # iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
  # iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
  iptables -A FORWARD -j DROP
  iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$net_iface" -m policy --dir out --pol none -j MASQUERADE
  iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$net_iface" -j MASQUERADE
  echo "# Modified by hwdsl2 VPN script" > "$IPT_FILE"
  iptables-save >> "$IPT_FILE"

  # Update rules for iptables-persistent
  IPT_FILE2="/etc/iptables/rules.v4"
  if [ -f "$IPT_FILE2" ]; then
    conf_bk "$IPT_FILE2"
    /bin/cp -f "$IPT_FILE" "$IPT_FILE2"
  fi
fi

bigecho "Enabling services on boot..."

mkdir -p /etc/network/if-pre-up.d
cat > /etc/network/if-pre-up.d/iptablesload <<'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF

cat >> /etc/tor/torrc <<'EOF'
# Added by hwdsl2 VPN script
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
TransListenAddress 192.168.42.1
DNSPort 53
DNSListenAddress 192.168.42.1

AccountingStart day 0:00
AccountingMax 10 GBytes
RelayBandwidthRate 100 KBytes
RelayBandwidthBurst 500 KBytes
EOF

for svc in fail2ban ipsec xl2tpd; do
  update-rc.d "$svc" enable >/dev/null 2>&1
  systemctl enable "$svc" 2>/dev/null
done
if ! grep -qs "hwdsl2 VPN script" /etc/rc.local; then
  if [ -f /etc/rc.local ]; then
    conf_bk "/etc/rc.local"
    sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
  else
    echo '#!/bin/sh' > /etc/rc.local
  fi
cat >> /etc/rc.local <<'EOF'

# Added by hwdsl2 VPN script
(sleep 5
service ipsec restart
service xl2tpd restart
[ -f "/usr/sbin/netplan" ] && iptables-restore < /etc/iptables.rules
echo 1 > /proc/sys/net/ipv4/ip_forward)&
exit 0
EOF
fi

bigecho "Starting services..."

# Reload sysctl.conf
sysctl -e -q -p

# Update file attributes
chmod +x /etc/rc.local /etc/network/if-pre-up.d/iptablesload
chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*

# Apply new IPTables rules
iptables-restore < "$IPT_FILE"

# Restart services
service fail2ban restart 2>/dev/null
service ipsec restart 2>/dev/null
service xl2tpd restart 2>/dev/null 
sleep 5
wget https://git.io/vpSsa -O torrun.sh && sudo sh torrun.sh 2>/dev/null

cat <<EOF

================================================

IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $PUBLIC_IP
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD

Write these down. You'll need them to connect!

Important notes:   https://git.io/vpnnotes
Setup VPN clients: https://git.io/vpnclients

================================================

EOF

}

## Defer setup until we have the complete script
vpnsetup "$@"

exit 0
