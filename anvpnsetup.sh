#!/bin/sh



YOUR_IPSEC_PSK=''
YOUR_USERNAME=''
YOUR_PASSWORD=''



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
  VPN_IPSEC_PSK="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 8)"
  VPN_USER=vpnuser
  VPN_PASSWORD="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 8)"
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
  modecfgdns="DNS_SRV2"
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
ms-dns $DNS_SRV1
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
"vpnuser" l2tpd "3Mn3qxTBrqgYufj6" *
"wHtA3R8c" l2tpd "pe8G4Ar6Es" *
"Wx2HwhrV" l2tpd "j36RJMSs24" *
"P3ebxT8p" l2tpd "Q9XBTy3cwr" *
"gR83jqBT" l2tpd "MR9bjurAmE" *
"jw4emLUX" l2tpd "kzWQ7SNphv" *
"pYF3aUhd" l2tpd "skG5tLEJhu" *
"Nq9V7rBK" l2tpd "he7XVKB5Cx" *
"rDg3JnG9" l2tpd "gG2wZKe6nW" *
"a2sZqYdX" l2tpd "twXgJ7Ba4r" *
"Mu7dV2kJ" l2tpd "kU97HeZ5Fu" *
"MoCareful" l2tpd "bobudo68" *
"MoSlim" l2tpd "nuvufe28" *
"MoGrotesque" l2tpd "zizale68" *
"MoSecret" l2tpd "lofiso18" *
"MoFree" l2tpd "welaxa58" *
"MoAfraid" l2tpd "haruri53" *
"MoMotionless" l2tpd "xebiya61" *
"MoRacial" l2tpd "vugefi10" *
"MoEmbarrassed" l2tpd "giyile50" *
"MoIntelligent" l2tpd "hejiti58" *
"MoFunctional" l2tpd "tipole98" *
"MoLaughable" l2tpd "jozata60" *
"MoFrequent" l2tpd "tusimi10" *
"MoFlashy" l2tpd "fixegu50" *
"MoZany" l2tpd "govonu13" *
"MoModern" l2tpd "sebihu98" *
"MoNice" l2tpd "vayupi60" *
"MoMeasly" l2tpd "jujixo22" *
"MoAwake" l2tpd "vibopa17" *
"MoCute" l2tpd "fatuwi12" *
"MoTangible" l2tpd "vusiro20" *
"MoAmuck" l2tpd "jocelo73" *
"MoNumberless" l2tpd "hehoso67" *
"MoUpbeat" l2tpd "jifamu29" *
"MoIgnorant" l2tpd "voxite70" *
"MoWholesale" l2tpd "kuvebe32" *
"MoTacit" l2tpd "vinavo27" *
"MoTested" l2tpd "kuyacu35" *
"MoSpotted" l2tpd "wudehe30" *
"MoSnobbish" l2tpd "xebucu38" *
"MoSwift" l2tpd "jetowu77" *
"MoSalty" l2tpd "kofara40" *
"MoDistinct" l2tpd "zepala92" *
"MoSimple" l2tpd "kihesa87" *
"MoDamaged" l2tpd "zesezo94" *
"MoPast" l2tpd "xuxasa89" *
"MoStrong" l2tpd "zojino52" *
"MoFirst" l2tpd "yeneta92" *
"MoLively" l2tpd "maloce55" *
"MoGrandiose" l2tpd "yodave49" *
"MoGiddy" l2tpd "zubice56" *
"MoGreat" l2tpd "liguwe97" *
"MoReminiscent" l2tpd "nufodu59" *
"MoTense" l2tpd "papoyi67" *
"MoSmelly" l2tpd "bahasi17" *
"MoPricey" l2tpd "pusumo24" *
"MoBeneficial" l2tpd "baxega19" *
"MoLonely" l2tpd "cevemo26" *
"QuFrantic" l2tpd "nunugi21" *
"QuUseless" l2tpd "rolubo29" *
"QuOverrated" l2tpd "siwuwe82" *
"QuYummy" l2tpd "donape77" *
"QuDelicious" l2tpd "suloku39" *
"QuRabid" l2tpd "dusiru34" *
"QuPerpetual" l2tpd "fepulu41" *
"QuEnormous" l2tpd "ruhose37" *
"QuGifted" l2tpd "tafozi89" *
"QuStanding" l2tpd "hucava96" *
"QuOutgoing" l2tpd "gawuma46" *
"QuTidy" l2tpd "votuvo54" *
"QuFuturistic" l2tpd "guyabi48" *
"QuIll-informed" l2tpd "howiwe11" *
"QuPathetic" l2tpd "tuneco96" *
"QuEmpty" l2tpd "wayuxu14" *
"QuCharming" l2tpd "xokefi21" *
"QuVerdant" l2tpd "jupaye61" *
"QuFierce" l2tpd "kozati24" *
"QuUtopian" l2tpd "wesozu19" *
"QuAutomatic" l2tpd "lacevi26" *
"QuAnnoyed" l2tpd "johimu66" *
"QuDemonic" l2tpd "lugiva73" *
"QuAbnormal" l2tpd "wayobu23" *
"QuNutty" l2tpd "yewojo76" *
"QuComplex" l2tpd "zitoru38" *
"QuFaulty" l2tpd "loyika33" *
"QuFanatical" l2tpd "bikife86" *
"QuOdd" l2tpd "yopeye81" *
"QuOrganic" l2tpd "bumagi88" *
"QuQuarrelsome" l2tpd "lifilo83" *
"QuZealous" l2tpd "nopigu46" *
"QuRuddy" l2tpd "cimeno98" *
"QuGlistening" l2tpd "bogovi94" *
"QuHungry" l2tpd "redaco11" *
"QuCloudy" l2tpd "najewa50" *
"QuMighty" l2tpd "dotude13" *
"QuSelfish" l2tpd "nuyaxi98" *
"QuJazzy" l2tpd "daxafo16" *
"QuAbsurd" l2tpd "fivizu23" *
"HyWorried" l2tpd "dazufo18" *
"HyQuickest" l2tpd "guxebi25" *
"HyUgliest" l2tpd "vivewo79" *
"HyAbsent" l2tpd "tababi73" *
"HyOld" l2tpd "hiluwo80" *
"HyThoughtful" l2tpd "tiropa76" *
"HyHeavy" l2tpd "vunoxo83" *
"HyMean" l2tpd "gugara78" *
"HyHandsome" l2tpd "jeruyo40" *
"HyAberrant" l2tpd "tekofa35" *
"HyGentle" l2tpd "wavoze43" *
"HyUncovered" l2tpd "geziso83" *
"HySlippery" l2tpd "jaxizu45" *
"HyDefiant" l2tpd "hayuvi35" *
"HyEvanescent" l2tpd "wehaka87" *
"HyWasteful" l2tpd "jokeya89" *
"HyKnotty" l2tpd "siwuxi34" *
"HySticky" l2tpd "sulali81" *
"HyReady" l2tpd "gucuza84" *
"HyInnate" l2tpd "gefazi86" *
"HyJittery" l2tpd "rapadi86" *
"HyMisty" l2tpd "dufusi88" *
"HyShocking" l2tpd "rewiga46" *
"HyAback" l2tpd "releto93" *
"HySecretive" l2tpd "xozuho78" *
"HyImaginary" l2tpd "xarove35" *
"HyExcellent" l2tpd "yigeju83" *
"HyHellish" l2tpd "lejaku85" *
"HyWakeful" l2tpd "yozulu88" *
"HyAcid" l2tpd "yopaya45" *
"HySloppy" l2tpd "yigeza47" *
"HyHanging" l2tpd "zijina51" *
"HyFumbling" l2tpd "melupo98" *
"HyBrief" l2tpd "devofu68" *
"HyLean" l2tpd "daxuta25" *
"HyGiant" l2tpd "dizeti72" *
"HyCapricious" l2tpd "ridiva74" *
"HyUnique" l2tpd "dugowa33" *
"HyObeisant" l2tpd "sowuxe35" *
"HyVacuous" l2tpd "somoxo37" *
"HyAloof" l2tpd "wovana97" *
"HyPrecious" l2tpd "wiyuba55" *
"HyDefective" l2tpd "wubaco57" *
"HyVast" l2tpd "jerere60" *
"HyAhead" l2tpd "zozeta74" *
"HyResonant" l2tpd "zapuva76" *
"HyThree" l2tpd "nisovo34" *
"HyTan" l2tpd "bijuja37" *
"YeTeeny" l2tpd "neloxo39" *
"YeBoring" l2tpd "boniye41" *
"YeDapper" l2tpd "soxena12" *
"YeFunny" l2tpd "famaca14" *
"YeSubsequent" l2tpd "sureco16" *
"YeSedate" l2tpd "getado20" *
"YeMassive" l2tpd "tejefe66" *
"YeExtra-small" l2tpd "xefova36" *
"YeAccurate" l2tpd "xavijo39" *
"YeItchy" l2tpd "xixowa86" *
"YeFast" l2tpd "kinixe44" *
"YeFluttering" l2tpd "yurele46" *
"YePlausible" l2tpd "logime48" *
"YeSuper" l2tpd "papepa63" *
"YeRobust" l2tpd "cifore66" *
"YeAwful" l2tpd "pijuro69" *
"YeGaping" l2tpd "pulose26" *
"YeLarge" l2tpd "cebege28" *
"YeSore" l2tpd "rasivu30" *
"YeDazzling" l2tpd "hamake46" *
"YePurple" l2tpd "hapolo93" *
"YeGrouchy" l2tpd "hutuye96" *
"YeWorthless" l2tpd "hewemu53" *
"YeDispensable" l2tpd "halini56" *
"YeUnarmed" l2tpd "yohedo25" *
"YeOrdinary" l2tpd "maxofe28" *
"YeDelicate" l2tpd "zizefe30" *
"YeAcoustic" l2tpd "meratu33" *
"YeAssorted" l2tpd "vimiba22" *
"YeLoutish" l2tpd "hiroco25" *
"YeBelligerent" l2tpd "wugudo73" *
"YeGainful" l2tpd "jejodo76" *
"YeHigh" l2tpd "jazeso32" *
"YeShivering" l2tpd "japote34" *
"YeJumpy" l2tpd "wiguge82" *
"YeAmused" l2tpd "wejovu40" *
"YeDidactic" l2tpd "kolewu42" *
"YeDetailed" l2tpd "novelu57" *
"YeHarmonious" l2tpd "xufuxa47" *
"YeWeary" l2tpd "kuhala95" *
"YeAngry" l2tpd "nudinu65" *
"YeVoracious" l2tpd "netepu22" *
"YeSilly" l2tpd "yifepo57" *
"YePossessive" l2tpd "livape59" *
"YeLoud" l2tpd "cipufo29" *
"YeRedundant" l2tpd "pesega76" *
"YeFalse" l2tpd "pewive79" *
"YeNaive" l2tpd "polawe36" *
"YeSpiteful" l2tpd "ricuku84" *
"YeLow" l2tpd "refoxu86" *
"YeRelieved" l2tpd "rovulu89" *
"YeHeavenly" l2tpd "hedune59" *
"YeTwo" l2tpd "vatipo16" *
"YeCurved" l2tpd "vawedu64" *
"YeLavish" l2tpd "humidu66" *
"YePumped" l2tpd "hepose23" *
"YeBouncy" l2tpd "xutepo36" *
"YeSteep" l2tpd "yipufo88" *
"YeSore" l2tpd "vebari33" *
"YeTalented" l2tpd "vorofi80" *
"YeYoung" l2tpd "watito83" *
"YeMoldy" l2tpd "jikovo85" *
"YeCourageous" l2tpd "gibeji36" *
"YeGuarded" l2tpd "gidiwi82" *
"YeCrooked" l2tpd "guveka85" *
"YeEfficacious" l2tpd "tokala87" *
"YeWrong" l2tpd "bunona40" *
"YeEasy" l2tpd "xocane78" *
"YeUnwieldy" l2tpd "jehuve28" *
"YeNear" l2tpd "vinazo68" *
"YeUppity" l2tpd "soguti62" *
"YeBlack" l2tpd "delaze12" *
"YeNecessary" l2tpd "sajohi20" *
"YePiquant" l2tpd "rabumi15" *
"YeRipe" l2tpd "guyeha67" *
"YeWandering" l2tpd "difani17" *
"YeStereotyped" l2tpd "tucajo25" *
"YeSoft" l2tpd "vimaro77" *
"YeAbrupt" l2tpd "tofuxo27" *
"YeWomanly" l2tpd "wucese35" *
"YeMinor" l2tpd "gawaye74" *
"YeGrateful" l2tpd "wugige82" *
"YeStale" l2tpd "taleze32" *
"YeThundering" l2tpd "jejohu84" *
"YeRight" l2tpd "hubimu35" *
"YePetite" l2tpd "womahu42" *
"YeSpotty" l2tpd "hesebe37" *
"YeUbiquitous" l2tpd "wapewa89" *
"YeUnderstood" l2tpd "vavipu39" *
"YeEntertaining" l2tpd "wifuxi92" *
"YeHealthy" l2tpd "hixeri42" *
"YeUnsightly" l2tpd "xewela49" *
"YeMerciful" l2tpd "hubiri89" *
"YeKindhearted" l2tpd "xeyulo97" *
"YeFeigned" l2tpd "vudefa92" *
"YeThreatening" l2tpd "xibemo54" *
"YeMalicious" l2tpd "heguga48" *
"YeElegant" l2tpd "xusine11" *
"YeDefeated" l2tpd "joxeva96" *
"YeCheap" l2tpd "xevape14" *
"YeUnbiased" l2tpd "wamiva99" *
"YeCeaseless" l2tpd "xelice62" *
"YeSable" l2tpd "zijela70" *
"YeVenomous" l2tpd "lanore64" *
"YeProductive" l2tpd "zuyoli26" *
"YeHalting" l2tpd "yirusu21" *
"YePastoral" l2tpd "monezi74" *
"YeTranquil" l2tpd "lihoti69" *
"YeFearless" l2tpd "mafano31" *
"YeHumdrum" l2tpd "cupiwe84" *
"YeDear" l2tpd "bihena33" *
"YeGodly" l2tpd "cefexe41" *
"YeLearned" l2tpd "bixace36" *
"YeMellow" l2tpd "cowike89" *
"YeDeranged" l2tpd "bunero38" *
"YeZippy" l2tpd "dileli91" *
"YeFive" l2tpd "berife86" *
"YeThin" l2tpd "dubimu93" *
"YeVague" l2tpd "bovutu89" *
"YeMute" l2tpd "desoba96" *
"YeClever" l2tpd "focewo59" *
"YeMelted" l2tpd "devani53" *
"testlog" l2tpd "testpass" *
"test" l2tpd "test" *
"testing" l2tpd "testing" *
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
  # VPN to Tor Routing
  iptables -t nat -A PREROUTING -i ppp+ -p udp --dport 53 -j REDIRECT --to-ports 5353
  iptables -t nat -A PREROUTING -i ppp+ -p tcp --syn -j REDIRECT --to-ports 9040
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
DNSPort 5353
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
(sleep 15
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
/etc/init.d/tor restart 2>/dev/null

 sleep 2
cat <<EOF

================================================

L2TP VPN+TOR\ Cisco IPsec server is now ready for use!

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
