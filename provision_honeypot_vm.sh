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
  local s="${1-}"
  if [[ -z "$s" ]]; then
    return 1
  fi
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
    local info_json
    info_json=$(qemu-img info --output json "$path" 2>/dev/null || true)
    if [[ -z "$info_json" ]]; then
      echo ""
      return 1
    fi
    printf '%s' "$info_json" | python3 -c 'import sys,json; s=sys.stdin.read().strip();
try:
    d=json.loads(s) if s else {}
    print(int(d.get("virtual-size",0)))
except Exception:
    sys.exit(1)'
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
# Provision d'une VM Proxmox (PVE) prête pour un honeypot (T-Pot CE)
# - S'exécute SUR le noeud Proxmox (root@pve)
# - Utilise une image cloud Ubuntu 22.04 et cloud-init
# - Crée un snippet user-data pour installer T-Pot CE au premier boot
# - Supporte un profil: --profile hive | sensor (par défaut: hive)
# ------------------------------------------------------------
# Dépendances côté PVE: qm, pvesm, curl, qemu-img
# ------------------------------------------------------------
# Exemple d'usage:
#   bash provision_honeypot_vm.sh \
#     --vmid 9001 \
#     --name tpot-ubuntu22 \
#     --storage local-lvm \
#     --bridge vmbr1 \
#     --vlan 30 \
#     --disk 64G \
#     --memory 8192 \
#     --cores 2 \
#     --ip 192.168.30.50/24 \
#     --gw 192.168.30.1 \
#     --ssh-pubkey "/root/.ssh/id_rsa.pub" \
#     --profile hive
#
# DHCP (au lieu d'une IP statique):
#   --dhcp
# ------------------------------------------------------------

# Valeurs par défaut
VMID=""
NAME="tpot-ubuntu22"
STORAGE="local-lvm"            # stockage pour le disque VM (contenu: images)
CI_STORAGE="local"             # stockage supportant les snippets (souvent 'local')
BRIDGE="vmbr0"
BRIDGE_USER_SET=false
VLAN_TAG=""
DISK_SIZE="64G"
MEMORY_MB="8192"
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
# T-Pot profil (hive | sensor)
TPOT_PROFILE="hive"
# Forcer malgré ressources insuffisantes
FORCE=false
# Image cloud
UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
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
  --profile <hive|sensor>     Profil T-Pot à installer (defaut: ${TPOT_PROFILE})
  --force                     Ignorer les vérifications de ressources minimales
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
    --bridge) BRIDGE="$2"; BRIDGE_USER_SET=true; shift 2 ;;
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
    --profile) TPOT_PROFILE="$2"; shift 2 ;;
    --force) FORCE=true; shift ;;
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

# Pré-checks outils et stockage
if [[ $(id -u) -ne 0 ]]; then
  log_err "Ce script doit être exécuté en root sur un nœud Proxmox."
  exit 1
fi
command -v pvesh >/dev/null 2>&1 || { log_err "pvesh introuvable. Exécuter sur un nœud Proxmox."; exit 1; }
command -v qm >/dev/null 2>&1 || { log_err "qm introuvable. Exécuter sur un nœud Proxmox."; exit 1; }
command -v pvesm >/dev/null 2>&1 || { log_err "pvesm introuvable. Exécuter sur un nœud Proxmox."; exit 1; }

# Validation et auto-détection du bridge réseau
AVAILABLE_BRIDGES=$(ls /sys/class/net 2>/dev/null | grep -E '^vmbr[0-9]+' | sort || true)
if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
  if [[ -n "${AVAILABLE_BRIDGES}" ]]; then
    FALLBACK_BRIDGE=$(echo "${AVAILABLE_BRIDGES}" | head -n1)
    if [[ "${BRIDGE_USER_SET}" == true ]]; then
      log_warn "Le bridge '${BRIDGE}' n'existe pas. Bascule automatique sur '${FALLBACK_BRIDGE}'. Utilisez --bridge pour choisir un autre bridge."
    else
      log_info "Bridge '${BRIDGE}' introuvable. Auto-détection: utilisation de '${FALLBACK_BRIDGE}'."
    fi
    BRIDGE="${FALLBACK_BRIDGE}"
  fi
fi
if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
  log_err "Aucun bridge réseau valide détecté sur ce nœud Proxmox."
  echo "\nSuggestions:" >&2
  echo "- Créez un bridge (ex: vmbr0) via l'UI: Datacenter > Node > System > Network" >&2
  echo "  puis appliquez la configuration réseau (ifreload -a) avant de relancer." >&2
  exit 1
fi

# Validation des stockages
log_info "Validation des stockages"
# Vérifier le stockage disque (images)
if ! pvesm status | awk 'NR>1{print $1}' | grep -qx "${STORAGE}"; then
  log_err "Le stockage --storage='${STORAGE}' est introuvable."; pvesm status | awk 'NR==1 || NR>1{print $1, $2, $3, $4}' >&2 || true; exit 1
fi
STORAGE_CONTENTS=$(pvesm config "${STORAGE}" 2>/dev/null | awk -F': ' '/^\s*content:/{print $2}' || true)
if [[ -n "${STORAGE_CONTENTS}" ]] && ! echo "${STORAGE_CONTENTS}" | grep -qw "images"; then
  log_err "Le stockage '${STORAGE}' ne supporte pas le contenu 'images'. Contenu actuel: ${STORAGE_CONTENTS}"
  exit 1
fi
log_ok "Stockage '${STORAGE}' prêt (images)"

# Vérifier CI_STORAGE et activer snippets si nécessaire
if [[ "${CI_STORAGE}" != "local" ]]; then
  log_warn "--ci-storage='${CI_STORAGE}' fourni, mais ce script écrit dans '/var/lib/vz/snippets' (stockage 'local'). Utilisation forcée de CI_STORAGE='local'."
  CI_STORAGE="local"
fi
if ! pvesm status | awk 'NR>1{print $1}' | grep -qx "${CI_STORAGE}"; then
  log_err "Le stockage CI '${CI_STORAGE}' est introuvable."; exit 1
fi
CI_CONTENTS=$(pvesm config "${CI_STORAGE}" 2>/dev/null | awk -F': ' '/^\s*content:/{print $2}' || true)
if ! echo "${CI_CONTENTS}" | grep -qw "snippets"; then
  log_warn "Activation du contenu 'snippets' sur '${CI_STORAGE}'"
  if ! pvesm set "${CI_STORAGE}" --content "images,iso,backup,vztmpl,snippets" >/dev/null 2>&1; then
    log_err "Impossible d'activer 'snippets' sur '${CI_STORAGE}'"
    exit 1
  fi
fi
log_ok "Snippets disponibles sur '${CI_STORAGE}'"

# Préparation
mkdir -p "${WORKDIR}"
IMAGE_PATH="${WORKDIR}/ubuntu-22.04.img"
SNIPPET_DIR="/var/lib/vz/snippets"
USER_SNIPPET_PATH="${SNIPPET_DIR}/${SNIPPET_NAME_PREFIX}-${VMID}-user.yaml"

log_info "Dossier de travail: ${WORKDIR}"
run "Création du dossier de travail" mkdir -p "${WORKDIR}"

# Téléchargement image si besoin
if [[ ! -f "${IMAGE_PATH}" ]]; then
  log_info "Téléchargement de l'image Ubuntu 22.04 cloud"
  run "Téléchargement image Ubuntu 22.04" curl -fL "${UBUNTU_IMAGE_URL}" -o "${IMAGE_PATH}"
else
  log_info "Image Ubuntu trouvée en cache: ${IMAGE_PATH}"
fi

# Vérifications de ressources minimales selon le profil
bytes_disk_target=$(size_to_bytes "${DISK_SIZE}" || echo "")
if [[ -z "${bytes_disk_target}" ]]; then
  log_warn "Impossible de calculer la taille disque cible; les vérifications de ressources seront ignorées."
else
  # Seuils depuis la documentation T-Pot CE
  if [[ "${TPOT_PROFILE}" == "hive" ]]; then
    MIN_RAM_MB=16384
    MIN_DISK_BYTES=$((256*1024*1024*1024))
  else
    MIN_RAM_MB=8192
    MIN_DISK_BYTES=$((128*1024*1024*1024))
  fi
  if [[ "${FORCE}" != true ]]; then
    if (( MEMORY_MB < MIN_RAM_MB )); then
      log_err "RAM insuffisante pour le profil '${TPOT_PROFILE}'. Requis: ${MIN_RAM_MB} MB, fourni: ${MEMORY_MB} MB (utilisez --force pour ignorer)."; exit 1
    fi
    if (( bytes_disk_target < MIN_DISK_BYTES )); then
      log_err "Disque insuffisant pour le profil '${TPOT_PROFILE}'. Requis: $(printf '%.0f' $(echo "${MIN_DISK_BYTES}/1024/1024/1024" | bc -l))G, fourni: ${DISK_SIZE} (utilisez --force pour ignorer)."; exit 1
    fi
  else
    log_warn "Mode --force: vérifications de ressources minimales ignorées (profil ${TPOT_PROFILE})."
  fi
fi

# Redimensionner le disque si demandé (sécurisé)
if [[ -n "${DISK_SIZE}" ]]; then
  cur_bytes=$(get_image_virtual_size_bytes "${IMAGE_PATH}" || echo "")
  tgt_bytes=$(size_to_bytes "${DISK_SIZE}" || echo "")
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
  --vga std

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
  - qemu-guest-agent
  - curl
  - ca-certificates
  - git
  - jq
  - sudo

runcmd:
  - [ bash, -lc, "systemctl enable --now qemu-guest-agent || true" ]
  - [ bash, -lc, "set -euo pipefail" ]
  - [ bash, -lc, "usermod -aG sudo ${CI_USER} || true" ]
  - [ bash, -lc, "echo '${CI_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-${CI_USER}-nopasswd && chmod 440 /etc/sudoers.d/90-${CI_USER}-nopasswd" ]
  - [ bash, -lc, "sudo -u ${CI_USER} bash -lc 'git clone https://github.com/telekom-security/tpotce ~/tpotce || (cd ~/tpotce && git pull --rebase)'" ]
  - [ bash, -lc, "sudo -u ${CI_USER} bash -lc 'chmod +x ~/tpotce/install.sh'" ]
  - [ bash, -lc, "sudo -u ${CI_USER} bash -lc 'TPOT_PROFILE=${TPOT_PROFILE} ~/tpotce/install.sh || true'" ]
  - [ bash, -lc, "echo 'NOTE: l\'installateur T-Pot CE (~/tpotce/install.sh) peut être interactif et peut redémarrer la machine. Si nécessaire, connectez-vous en tant que ${CI_USER} et relancez: ~/tpotce/install.sh'" ]

write_files:
  - path: /etc/motd
    permissions: '0644'
    content: |
      Attention: système sous supervision (T-Pot CE en cours d'installation).

final_message: "Cloud-init terminé pour ${NAME}. L'installation T-Pot CE peut continuer/redémarrer selon l'installateur."
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

    # Fallback: tentative de détection IP via ARP/MAC sur le bridge (utile si QGA KO)
    if [[ "${USE_DHCP}" == true ]]; then
      mac=$(qm config "${VMID}" | awk -F'[=, ]' '/^net0:/ {print $3}')
      if [[ -n "${mac}" ]]; then
        mac_lc=$(echo "${mac}" | tr '[:upper:]' '[:lower:]')
        candidates=$(ip neigh show dev "${BRIDGE}" 2>/dev/null | awk -v m="${mac_lc}" 'BEGIN{IGNORECASE=1} index($0,m){print $1}')
        if [[ -n "${candidates}" ]]; then
          log_info "IP candidate(s) détectée(s) via ARP/MAC (${mac_lc}) sur ${BRIDGE}:"
          echo "${candidates}" | sed 's/^/  - /'
        else
          log_warn "Aucune IP trouvée via ARP pour MAC ${mac_lc} sur ${BRIDGE}."
        fi
      else
        log_warn "Impossible de récupérer la MAC de net0 via 'qm config ${VMID}'."
      fi
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
  - T-Pot service:        systemctl status tpot (dans la VM)

Réseau:
  - Mode: $( [[ "${USE_DHCP}" == true ]] && echo "DHCP (auto)" || echo "Statique ${IP_ADDR} (GW ${GW_ADDR})" )

Sécurité:
  - Ce honeypot écoute sur SSH et journalise les interactions.
  - Placez la VM sur votre réseau interne isolé (bridge ${BRIDGE}${VLAN_TAG:+, VLAN ${VLAN_TAG}}).
EON
