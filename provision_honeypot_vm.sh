#!/usr/bin/env bash
set -euo pipefail

# Couleurs et helpers de log
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"

log_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }

# Convertit des tailles humaines (ex: 8G, 10240M) en octets
size_to_bytes() {
  local s="$1"
  # Utiliser python3 si dispo pour plus de robustesse
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import sys, re
s = sys.stdin.read().strip()
m = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([KMGTP]?B?)?\s*", s)
if not m:
    sys.exit(1)
val = float(m.group(1))
unit = (m.group(2) or '').upper().rstrip('B')
mult = {
    '': 1,
    'K': 1024,
    'M': 1024**2,
    'G': 1024**3,
    'T': 1024**4,
    'P': 1024**5,
}.get(unit, None)
if mult is None:
    sys.exit(1)
print(int(val * mult))
PY
    return $?
  fi
  # Fallback bash simple (K/M/G)
  s=$(echo "$s" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
  local num unit
  num=${s%%[KMGTPB]*}
  unit=${s#$num}
  case "$unit" in
    K* ) echo $((num*1024)) ;;
    M* ) echo $((num*1024*1024)) ;;
    G* ) echo $((num*1024*1024*1024)) ;;
    T* ) echo $((num*1024*1024*1024*1024)) ;;
    P* ) echo $((num*1024*1024*1024*1024*1024)) ;;
    *  ) echo "$num" ;;
  esac
}

# Récupère la taille virtuelle actuelle de l'image (en octets)
get_image_virtual_size_bytes() {
  local path="$1"
  # Essayer json via python3
  if command -v python3 >/dev/null 2>&1; then
    qemu-img info --output json "$path" 2>/dev/null | python3 - <<'PY'
import sys, json
data = json.load(sys.stdin)
print(int(data.get('virtual-size', 0)))
PY
    return $?
  fi
  # Fallback: grep virtual size
  qemu-img info "$path" 2>/dev/null | awk -F'[() ]+' '/virtual size/ {print $4}'
}
log_warn() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }
log_ok()   { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET}  $*"; }
log_err()  { echo -e "${COLOR_RED}[ERREUR]${COLOR_RESET} $*"; }

run() {
  local desc="$1"; shift
  echo -ne "${COLOR_BLUE}[*]${COLOR_RESET} ${desc} ... "
  if "$@"; then
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
  else
    echo -e "${COLOR_RED}ECHEC${COLOR_RESET}"
    log_err "Echec lors de: ${desc}"
    exit 1
  fi
}

# Helpers Proxmox
get_next_vmid() {
  # Essaie via pvesh
  if command -v pvesh >/dev/null 2>&1; then
    local id
    if id=$(pvesh get /cluster/nextid 2>/dev/null); then
      echo "${id}"
      return 0
    fi
  fi
  # Fallback: calcule depuis qm list
  local maxid
  maxid=$(qm list | awk 'NR>1 {print $1}' | sort -n | tail -n1)
  if [[ -z "${maxid}" ]]; then
    echo 100
  else
    echo $((maxid+1))
  fi
}

get_vm_ipv4() {
  # Requiert QGA
  local json
  if ! json=$(qm agent "${VMID}" network-get-interfaces 2>/dev/null); then
    return 1
  fi
  # Tente via python3 si dispo
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$json" <<'PY'
import sys, json
data = json.loads(sys.argv[1]) if len(sys.argv)>1 else json.load(sys.stdin)
for iface in data:
    if iface.get('name') == 'lo':
        continue
    for addr in iface.get('ip-addresses', []):
        if addr.get('ip-address-type') == 'ipv4' and addr.get('ip-address') != '127.0.0.1':
            print(addr['ip-address'])
            sys.exit(0)
sys.exit(1)
PY
    return $?
  fi
  # Fallback pauvre: grep la première IPv4 non loopback
  echo "${json}" | grep -E '"ip-address"' | grep -Eo '[0-9]+(\.[0-9]+){3}' | grep -v '^127\.' | head -n1
}

# ------------------------------------------------------------
# Provision d'une VM Proxmox (PVE) prête pour un honeypot (Cowrie)
# - S'exécute SUR le noeud Proxmox (root@pve)
# - Utilise une image cloud Debian 12 et cloud-init
# - Crée un snippet user-data pour installer Cowrie au premier boot
# ------------------------------------------------------------
# Dépendances côté PVE: qm, pvesm, curl, qemu-img
# ------------------------------------------------------------
# Exemple d'usage:
#   bash provision_honeypot_vm.sh \
#     --vmid 9001 \
#     --name hp-debian12 \
#     --storage local-lvm \
#     --bridge vmbr1 \
#     --vlan 30 \
#     --disk 10G \
#     --memory 2048 \
#     --cores 2 \
#     --ip 192.168.30.50/24 \
#     --gw 192.168.30.1 \
#     --ssh-pubkey "/root/.ssh/id_rsa.pub"
#
# DHCP (au lieu d'une IP statique):
#   --dhcp
# ------------------------------------------------------------

# Valeurs par défaut
VMID=""
NAME="honeypot-debian12"
STORAGE="local-lvm"            # stockage pour le disque VM (contenu: images)
CI_STORAGE="local"             # stockage supportant les snippets (souvent 'local')
BRIDGE="vmbr0"
VLAN_TAG=""
DISK_SIZE="8G"
MEMORY_MB="1024"
CORES="1"
CPU_TYPE="x86-64-v2-AES"
# Réseau: choisir DHCP ou IP statique via --dhcp ou --ip/--gw
USE_DHCP=false
IP_ADDR=""
GW_ADDR=""
DNS_SERVERS="1.1.1.1 8.8.8.8"
DNS_SEARCH=""
ALLOW_SHRINK=false
# Cloud-init user
CI_USER="honeypot"
CI_PASSWORD=""                  # si vide, non défini (clé SSH recommandée)
SSH_PUBKEY_PATH=""
# Image cloud
DEBIAN_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
WORKDIR="/tmp/pve-honeypot-build"
SNIPPET_NAME_PREFIX="honeypot"
ENABLE_QGA=true                  # qemu-guest-agent
START_VM=false                   # démarrage auto de la VM
WAIT_CLOUDINIT=false             # attendre la fin cloud-init (nécessite QGA)

usage() {
  cat <<EOF
Usage: $0 [--vmid <ID>] [options]

VMID:
  --vmid <ID>                 ID unique de la VM (ex: 9001). Si omis: auto (premier libre)

Options principales:
  --name <nom>                Nom de la VM (defaut: ${NAME})
  --storage <storage>         Stockage disque VM (defaut: ${STORAGE})
  --ci-storage <storage>      Stockage supportant snippets cloud-init (defaut: ${CI_STORAGE})
  --bridge <vmbrX>            Bridge réseau Proxmox (defaut: ${BRIDGE})
  --vlan <tag>                VLAN tag (optionnel)
  --disk <taille>             Taille du disque (defaut: ${DISK_SIZE})
  --memory <MB>               RAM en Mo (defaut: ${MEMORY_MB})
  --cores <N>                 Nombre de vCPU (defaut: ${CORES})
  --cpu-type <type>           Type CPU (defaut: ${CPU_TYPE})

Réseau (choisir l'un):
  --dhcp                      Utiliser DHCP
  --ip <CIDR>                 IP statique (ex: 192.168.30.50/24)
  --gw <IP>                   Passerelle (ex: 192.168.30.1)
  --dns "IP [IP...]"           DNS (defaut: "${DNS_SERVERS}")
  --dns-search <domain>       Domaine de recherche DNS

Cloud-init utilisateur:
  --ci-user <user>            Utilisateur (defaut: ${CI_USER})
  --ci-pass <password>        Mot de passe (optionnel)
  --ssh-pubkey <path>         Chemin vers la clé publique SSH à injecter

Divers:
  --no-qga                    Ne pas activer qemu-guest-agent
  --allow-shrink              Autoriser la réduction de l'image (qemu-img --shrink)
  --start                     Démarrer la VM automatiquement à la fin
  --wait-cloudinit            Attendre la fin de cloud-init (avec QGA)
  -h | --help                 Afficher l'aide
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vmid) VMID="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --ci-storage) CI_STORAGE="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --vlan) VLAN_TAG="$2"; shift 2 ;;
    --disk) DISK_SIZE="$2"; shift 2 ;;
    --memory) MEMORY_MB="$2"; shift 2 ;;
    --cores) CORES="$2"; shift 2 ;;
    --cpu-type) CPU_TYPE="$2"; shift 2 ;;
    --dhcp) USE_DHCP=true; shift ;;
    --ip) IP_ADDR="$2"; shift 2 ;;
    --gw) GW_ADDR="$2"; shift 2 ;;
    --dns) DNS_SERVERS="$2"; shift 2 ;;
    --dns-search) DNS_SEARCH="$2"; shift 2 ;;
    --ci-user) CI_USER="$2"; shift 2 ;;
    --ci-pass) CI_PASSWORD="$2"; shift 2 ;;
    --ssh-pubkey) SSH_PUBKEY_PATH="$2"; shift 2 ;;
    --no-qga) ENABLE_QGA=false; shift ;;
    --allow-shrink) ALLOW_SHRINK=true; shift ;;
    --start) START_VM=true; shift ;;
    --wait-cloudinit) WAIT_CLOUDINIT=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Option inconnue: $1"; usage; exit 1 ;;
  esac
done

# VMID auto si non fourni
if [[ -z "${VMID}" ]]; then
  log_info "Aucun VMID fourni: sélection automatique du premier ID libre"
  VMID=$(get_next_vmid)
  log_ok "VMID sélectionné: ${VMID}"
fi

if [[ "${USE_DHCP}" == false && -z "${IP_ADDR}" ]]; then
  echo "[INFO] Aucun --ip fourni, bascule en DHCP"
  USE_DHCP=true
fi

if [[ "${USE_DHCP}" == false && -z "${GW_ADDR}" ]]; then
  echo "[ERREUR] IP statique requiert --gw" >&2
  exit 1
fi

if [[ -n "${SSH_PUBKEY_PATH}" && ! -f "${SSH_PUBKEY_PATH}" ]]; then
  echo "[ERREUR] Fichier clé publique introuvable: ${SSH_PUBKEY_PATH}" >&2
  exit 1
fi

# Validation bridge réseau
if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
  log_err "Le bridge '${BRIDGE}' n'existe pas sur ce nœud Proxmox."
  echo "\nSuggestions:" >&2
  echo "- Utilisez un bridge existant (ex: --bridge vmbr0)" >&2
  echo "- Ou créez le bridge '${BRIDGE}' via l'UI (Datacenter > Node > System > Network)" >&2
  echo "  et appliquez la configuration réseau (ifreload -a) avant de relancer." >&2
  exit 1
fi

# Préparation
mkdir -p "${WORKDIR}"
IMAGE_PATH="${WORKDIR}/debian-12.qcow2"
SNIPPET_DIR="/var/lib/vz/snippets"
USER_SNIPPET_PATH="${SNIPPET_DIR}/${SNIPPET_NAME_PREFIX}-${VMID}-user.yaml"

log_info "Dossier de travail: ${WORKDIR}"
run "Création du dossier de travail" mkdir -p "${WORKDIR}"

# Téléchargement image si besoin
if [[ ! -f "${IMAGE_PATH}" ]]; then
  log_info "Téléchargement de l'image Debian 12 cloud"
  run "Téléchargement image Debian 12" curl -fL "${DEBIAN_IMAGE_URL}" -o "${IMAGE_PATH}"
else
  log_info "Image Debian trouvée en cache: ${IMAGE_PATH}"
fi

# Redimensionner le disque si demandé (sécurisé)
if [[ -n "${DISK_SIZE}" ]]; then
  cur_bytes=$(get_image_virtual_size_bytes "${IMAGE_PATH}" || echo "")
  tgt_bytes=$(size_to_bytes <<<"${DISK_SIZE}" || echo "")
  if [[ -z "$cur_bytes" || -z "$tgt_bytes" ]]; then
    log_warn "Impossible de déterminer les tailles actuelles/cibles, tentative de resize direct à ${DISK_SIZE}"
    run "Resize disque QCOW2 (best-effort)" qemu-img resize "${IMAGE_PATH}" "${DISK_SIZE}"
  else
    if (( tgt_bytes > cur_bytes )); then
      log_info "Agrandissement de l'image: $(printf '%d' "$cur_bytes") -> ${DISK_SIZE}"
      run "Resize (grow)" qemu-img resize "${IMAGE_PATH}" "${DISK_SIZE}"
    elif (( tgt_bytes < cur_bytes )); then
      if [[ "${ALLOW_SHRINK}" == true ]]; then
        log_warn "Réduction de l'image demandée: cela peut supprimer des données au-delà de ${DISK_SIZE}"
        run "Resize (shrink)" qemu-img resize --shrink "${IMAGE_PATH}" "${DISK_SIZE}"
      else
        log_warn "Taille cible (${DISK_SIZE}) < taille actuelle. Aucun shrink effectué (ajoutez --allow-shrink pour forcer)."
      fi
    else
      log_info "Taille de l'image déjà à ${DISK_SIZE}, pas de modification."
    fi
  fi
fi

# Créer la VM basique
NETCONF="virtio,bridge=${BRIDGE}"
if [[ -n "${VLAN_TAG}" ]]; then
  NETCONF+=",tag=${VLAN_TAG}"
fi

log_info "Création de la VM ${VMID} (${NAME})"
run "qm create ${VMID}" qm create "${VMID}" \
  --name "${NAME}" \
  --memory "${MEMORY_MB}" \
  --cores "${CORES}" \
  --cpu "${CPU_TYPE}" \
  --net0 "${NETCONF}" \
  --ostype l26 \
  --scsihw virtio-scsi-pci \
  --serial0 socket \
  --vga serial0

# Import du disque
log_info "Import du disque dans ${STORAGE}"
run "Import du disque" qm importdisk "${VMID}" "${IMAGE_PATH}" "${STORAGE}" --format qcow2

# Attacher le disque comme scsi0 et définir boot order
run "Attache disque scsi0" qm set "${VMID}" --scsi0 "${STORAGE}:vm-${VMID}-disk-0"
run "Configure boot order" qm set "${VMID}" --boot order=scsi0

# Ajouter lecteur cloud-init
run "Ajout lecteur cloud-init" qm set "${VMID}" --ide2 "${STORAGE}:cloudinit"

# Activer QGA si demandé
if [[ "${ENABLE_QGA}" == true ]]; then
  run "Activation Qemu Guest Agent" qm set "${VMID}" --agent enabled=1,fstrim_cloned_disks=1
fi

# Construire le snippet cloud-init user-data
run "Création dossier snippets" mkdir -p "${SNIPPET_DIR}"

SSHKEYS_CONTENT=""
if [[ -n "${SSH_PUBKEY_PATH}" ]]; then
  SSHKEYS_CONTENT="$(cat "${SSH_PUBKEY_PATH}")"
fi

IPCONFIG="ip=dhcp"
if [[ "${USE_DHCP}" == false ]]; then
  IPCONFIG="ip=${IP_ADDR},gw=${GW_ADDR}"
fi

cat > "${USER_SNIPPET_PATH}" <<EOF
#cloud-config
preserve_hostname: false
hostname: ${NAME}
manage_etc_hosts: true

users:
  - name: ${CI_USER}
    groups: [ adm, cdrom, dip, plugdev, sudo ]
    shell: /bin/bash
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    $( [[ -n "${CI_PASSWORD}" ]] && echo "passwd: $(openssl passwd -6 \"${CI_PASSWORD}\")" )
    $( [[ -n "${SSHKEYS_CONTENT}" ]] && echo "ssh_authorized_keys:\n      - ${SSHKEYS_CONTENT}" )

package_update: true
packages:
  - git
  - python3
  - python3-venv
  - python3-pip
  - virtualenv
  - libssl-dev
  - libffi-dev
  - build-essential
  - authbind
  - ufw

runcmd:
  - [ bash, -lc, "set -euo pipefail; id ${CI_USER} || true" ]
  - [ bash, -lc, "ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw --force enable" ]
  - [ bash, -lc, "adduser --disabled-password --gecos '' cowrie || true" ]
  - [ bash, -lc, "mkdir -p /opt/cowrie && chown cowrie:cowrie /opt/cowrie" ]
  - [ bash, -lc, "sudo -u cowrie python3 -m venv /opt/cowrie/venv" ]
  - [ bash, -lc, "sudo -u cowrie /opt/cowrie/venv/bin/pip install --upgrade pip wheel" ]
  - [ bash, -lc, "sudo -u cowrie git clone https://github.com/cowrie/cowrie.git /opt/cowrie/cowrie || true" ]
  - [ bash, -lc, "sudo -u cowrie /opt/cowrie/venv/bin/pip install -r /opt/cowrie/cowrie/requirements.txt" ]
  - [ bash, -lc, "sudo -u cowrie cp /opt/cowrie/cowrie/etc/cowrie.cfg.dist /opt/cowrie/cowrie/etc/cowrie.cfg || true" ]
  - [ bash, -lc, "echo 'shell.hostname = ${NAME}' >> /opt/cowrie/cowrie/etc/cowrie.cfg" ]
  - [ bash, -lc, "echo 'ssh_listen_port = 22' >> /opt/cowrie/cowrie/etc/cowrie.cfg" ]
  - [ bash, -lc, "echo 'telnet_enabled = false' >> /opt/cowrie/cowrie/etc/cowrie.cfg" ]
  - [ bash, -lc, "echo 'stdout = false' >> /opt/cowrie/cowrie/etc/cowrie.cfg" ]
  - [ bash, -lc, "if [ -f /etc/ssh/sshd_config ]; then sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config && systemctl restart ssh || true; fi" ]
  - [ bash, -lc, "cat >/etc/systemd/system/cowrie.service <<'UNIT'\n[Unit]\nDescription=Cowrie SSH Honeypot\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nUser=cowrie\nGroup=cowrie\nWorkingDirectory=/opt/cowrie/cowrie\nExecStart=/opt/cowrie/venv/bin/python /opt/cowrie/cowrie/bin/cowrie start -n\nExecStop=/opt/cowrie/venv/bin/python /opt/cowrie/cowrie/bin/cowrie stop\nRestart=always\nRestartSec=5s\n\n[Install]\nWantedBy=multi-user.target\nUNIT" ]
  - [ bash, -lc, "systemctl daemon-reload && systemctl enable --now cowrie" ]
  - [ bash, -lc, "ufw default deny outgoing" ]
  - [ bash, -lc, "ufw allow in on lo" ]
  - [ bash, -lc, "ufw allow out on lo" ]
  - [ bash, -lc, "ufw status verbose" ]

write_files:
  - path: /etc/motd
    permissions: '0644'
    content: |
      Attention: système sous supervision.

final_message: "Cloud-init terminé pour ${NAME}. Cowrie démarré."
EOF

# Appliquer config réseau/ssh/dns à la VM via qm set
if [[ -n "${DNS_SERVERS}" ]]; then
  run "Configurer DNS" qm set "${VMID}" --nameserver "${DNS_SERVERS}"
fi
if [[ -n "${DNS_SEARCH}" ]]; then
  run "Configurer searchdomain" qm set "${VMID}" --searchdomain "${DNS_SEARCH}"
fi
run "Configurer ciuser" qm set "${VMID}" --ciuser "${CI_USER}"
if [[ -n "${CI_PASSWORD}" ]]; then
  run "Configurer cipassword" qm set "${VMID}" --cipassword "${CI_PASSWORD}"
fi
if [[ -n "${SSHKEYS_CONTENT}" ]]; then
  run "Configurer sshkeys" qm set "${VMID}" --sshkeys "${SSH_PUBKEY_PATH}"
fi

# Lier le snippet user-data
run "Liaison user-data (cicustom)" qm set "${VMID}" --cicustom "user=${CI_STORAGE}:snippets/$(basename "${USER_SNIPPET_PATH}")"

# Config IP
run "Configuration IP (ipconfig0)" qm set "${VMID}" --ipconfig0 "${IPCONFIG}"

# Démarrage automatique et attente QGA/cloud-init
if [[ "${START_VM}" == true ]]; then
  run "Démarrage de la VM" qm start "${VMID}"
  if [[ "${WAIT_CLOUDINIT}" == true && "${ENABLE_QGA}" == true ]]; then
    log_info "Attente de l'agent QEMU (QGA) jusqu'à 300s"
    QGA_UP=false
    for i in $(seq 1 60); do
      if qm agent "${VMID}" ping >/dev/null 2>&1; then
        QGA_UP=true; break
      fi
      sleep 5
    done
    if [[ "${QGA_UP}" == true ]]; then
      log_ok "QGA disponible. Vous pouvez suivre cloud-init dans la VM."
      log_info "Conseil: journalctl -u cloud-init -n 200 --no-pager (dans la VM)"
      # Détection IP automatique (DHCP) via QGA
      if ip=$(get_vm_ipv4 2>/dev/null) && [[ -n "$ip" ]]; then
        log_ok "Adresse IP détectée: ${ip}"
      else
        log_warn "Impossible de détecter l'IP via QGA pour l'instant."
      fi
    else
      log_warn "QGA non disponible après délai. Cloud-init continue probablement en tâche de fond."
    fi
  fi
fi

# Conseils finaux
cat <<EON

[SUCCES] VM ${VMID} (${NAME}) créée.

Prochaines étapes:
  - Démarrer la VM:       qm start ${VMID}
  - Voir la console:      qm terminal ${VMID}
  - Vérifier cloud-init:  journalctl -u cloud-init -n 200 --no-pager (dans la VM)
  - Cowrie service:       systemctl status cowrie (dans la VM)

Réseau:
  - Mode: $( [[ "${USE_DHCP}" == true ]] && echo "DHCP (auto)" || echo "Statique ${IP_ADDR} (GW ${GW_ADDR})" )

Sécurité:
  - Ce honeypot écoute sur SSH et journalise les interactions.
  - Placez la VM sur votre réseau interne isolé (bridge ${BRIDGE}${VLAN_TAG:+, VLAN ${VLAN_TAG}}).
EON
