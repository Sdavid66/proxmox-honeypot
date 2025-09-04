#!/usr/bin/env bash
set -euo pipefail

# T-Pot Provisioner for Proxmox (PVE)
# Modes supportés:
# - mode ISO (par défaut):
#   * Télécharge (ou utilise) l'ISO T-Pot
#   * Crée une VM Proxmox prête à lancer l'installateur T-Pot depuis l'ISO
# - mode Debian13 (cloud-init, non interactif):
#   * Télécharge une image cloud Debian 13 (Trixie)
#   * Crée une VM Proxmox et configure cloud-init pour:
#       - locale FR (français), clavier suisse (ch-fr), fuseau Europe/Zurich
#       - installation de qemu-guest-agent, git, curl, jq, sudo
#       - git clone https://github.com/telekom-security/tpotce et exécution de install.sh
#   * Option de profil T-Pot (hive|sensor)
#   * DHCP ou IP statique
# - Sauvegarde la configuration de la VM dans un fichier local pour référence
#
# Utilisation basique (ISO):
#   ./tpot_iso_provision.sh \
#     --name tpot-iso \
#     --storage local-lvm \
#     --iso-storage local \
#     --bridge vmbr0 \
#     --disk 256G \
#     --memory 16384 \
#     --cores 4 \
#     --iso-url "<URL ISO T-Pot>" \
#     --start
#
# Utilisation basique (Debian 13, non-interactif):
#   ./tpot_iso_provision.sh \
#     --mode debian13 \
#     --name tpot-debian13 \
#     --storage local-lvm \
#     --bridge vmbr0 \
#     --disk 256G \
#     --memory 16384 \
#     --cores 4 \
#     --dhcp \
#     --profile hive \
#     --ssh-pubkey /root/.ssh/id_rsa.pub \
#     --start --wait-cloudinit
#
# Remarques ISO:
# - L'URL de l'ISO T-Pot est indiquée ici: https://github.security.telekom.com/2022/04/honeypot-tpot-22.04-released.html#download-iso-image
#   Exemple (à adapter aux versions publiées):
#   https://github.com/telekom-security/tpotce/releases/download/<version>/T-Pot-<version>.iso
# - Vous pouvez aussi fournir un ISO local via --iso-path /chemin/vers/T-Pot-*.iso (dans ce cas --iso-url est inutile).
# - L'ISO sera copié (si nécessaire) vers le stockage ISO (ex: local => /var/lib/vz/template/iso/).

COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"
log_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_ok()   { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET}  $*"; }
log_warn() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }
log_err()  { echo -e "${COLOR_RED}[ERREUR]${COLOR_RESET} $*"; }

usage() {
  cat <<EOF
Usage: $0 [--vmid <ID>] [options]

VMID:
  --vmid <ID>                 ID unique de la VM (ex: 9001). Si omis: auto (premier libre)

Options principales:
  --mode <iso|debian13>       Mode de provision (defaut: ${MODE})
  --name <nom>                Nom de la VM (defaut: ${NAME})
  --storage <storage>         Stockage disque VM (defaut: ${STORAGE})
  --iso-storage <storage>     Stockage pour ISOs (defaut: ${ISO_STORAGE})
  --bridge <vmbrX>            Bridge réseau Proxmox (defaut: ${BRIDGE})
  --vlan <tag>                VLAN tag (optionnel)
  --disk <taille>             Taille du disque (defaut: ${DISK_SIZE})
  --memory <MB>               RAM en Mo (defaut: ${MEMORY_MB})
  --cores <N>                 Nombre de vCPU (defaut: ${CORES})
  --cpu-type <type>           Type CPU (defaut: ${CPU_TYPE})

ISO (choisir l'un):
  --iso-url <url>             URL de l'ISO T-Pot à télécharger
  --iso-path <path>           Chemin local d'un ISO déjà téléchargé
  --latest                    Récupérer automatiquement la dernière ISO T-Pot depuis GitHub

Debian13 (réseau et utilisateur):
  --dhcp                      Utiliser DHCP (defaut si --ip non fourni)
  --ip <CIDR>                 IP statique (ex: 192.168.30.50/24)
  --gw <IP>                   Passerelle (ex: 192.168.30.1)
  --dns "IP [IP...]"           DNS (defaut: "${DNS_SERVERS}")
  --dns-search <domain>       Domaine de recherche DNS
  --ci-user <user>            Utilisateur cloud-init (defaut: ${CI_USER})
  --ci-pass <password>        Mot de passe utilisateur (optionnel)
  --ssh-pubkey <path>         Chemin vers la clé publique SSH à injecter
  --profile <hive|sensor>     Profil T-Pot à installer (defaut: ${TPOT_PROFILE})
  --wait-cloudinit            Attendre la disponibilité QGA/cloud-init (Debian13)

Divers:
  --enable-qga                Activer qemu-guest-agent dans la VM
  --start                     Démarrer la VM automatiquement à la fin
  -h | --help                 Afficher l'aide
EOF
}

# Valeurs par défaut
VMID=""
MODE="iso"                    # iso | debian13
NAME="tpot-iso"
STORAGE="local-lvm"           # disque VM (content: images)
ISO_STORAGE="local"           # stockage content: iso
BRIDGE="vmbr0"
VLAN_TAG=""
DISK_SIZE="256G"
MEMORY_MB="16384"
CORES="4"
CPU_TYPE="x86-64-v2-AES"
ENABLE_QGA=false
START_VM=false
ISO_URL=""
ISO_PATH=""
LATEST=false

# Debian13 / cloud-init options
USE_DHCP=true
IP_ADDR=""
GW_ADDR=""
DNS_SERVERS="1.1.1.1 8.8.8.8"
DNS_SEARCH=""
CI_USER="honeypot"
CI_PASSWORD=""
SSH_PUBKEY_PATH=""
TPOT_PROFILE="hive"           # hive | sensor
WAIT_CLOUDINIT=false
WORKDIR="/tmp/pve-honeypot-build"
DEBIAN_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-genericcloud-amd64-daily.qcow2"
USER_SNIPPET_PATH=""

# Helpers
get_next_vmid() {
  if command -v pvesh >/dev/null 2>&1; then
    pvesh get /cluster/nextid 2>/dev/null && return 0
  fi
  local maxid
  maxid=$(qm list | awk 'NR>1 {print $1}' | sort -n | tail -n1)
  if [[ -z "${maxid}" ]]; then echo 100; else echo $((maxid+1)); fi
}

pve_storage_path() {
  # Retourne la racine du stockage Proxmox (ex: pvesm path local => /var/lib/vz)
  pvesm path "$1" 2>/dev/null || true
}

resolve_latest_iso_url() {
  # Utilise l'API GitHub pour récupérer le tag le plus récent et tenter de trouver une ISO.
  local api="https://api.github.com/repos/telekom-security/tpotce/releases/latest"
  local json tag url
  json=$(curl -fsSL "$api") || return 1
  tag=$(echo "$json" | jq -r '.tag_name // empty')
  # 1) Essayer de trouver un asset .iso explicite
  url=$(echo "$json" | jq -r '.assets[] | select(.name | test("\\.iso$")) | .browser_download_url' | head -n1)
  if [[ -n "$url" && "$url" != "null" ]]; then
    echo "$url"; return 0
  fi
  # 2) Sinon, tenter des URLs candidates basées sur le tag
  if [[ -n "$tag" && "$tag" != "null" ]]; then
    local base="https://github.com/telekom-security/tpotce/releases/download/${tag}"
    local candidates=(
      "${base}/T-Pot-${tag}.iso"
      "${base}/T-Pot-${tag}-amd64.iso"
      "${base}/TPot-${tag}.iso"
    )
    for c in "${candidates[@]}"; do
      if curl -sfI "$c" >/dev/null 2>&1; then
        echo "$c"; return 0
      fi
    done
  fi
  log_err "Impossible de déterminer automatiquement l'URL de l'ISO (pas d'asset .iso et URLs candidates introuvables). Utilisez --iso-url ou fournissez --iso-path."
  return 1
}

ensure_snippets_local() {
  # Force l'utilisation du stockage 'local' pour snippets (cloud-init)
  if ! pvesm status | awk 'NR>1{print $1}' | grep -qx "local"; then
    log_err "Le stockage 'local' est introuvable pour les snippets cloud-init."
    exit 1
  fi
  local contents
  contents=$(pvesm config local 2>/dev/null | awk -F': ' '/^\s*content:/{print $2}' || true)
  if ! echo "${contents}" | grep -qw "snippets"; then
    log_warn "Activation du contenu 'snippets' sur 'local'"
    pvesm set local --content "images,iso,backup,vztmpl,snippets" >/dev/null 2>&1 || {
      log_err "Impossible d'activer 'snippets' sur 'local'"; exit 1; }
  fi
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --vmid) VMID="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --iso-storage) ISO_STORAGE="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --vlan) VLAN_TAG="$2"; shift 2 ;;
    --disk) DISK_SIZE="$2"; shift 2 ;;
    --memory) MEMORY_MB="$2"; shift 2 ;;
    --cores) CORES="$2"; shift 2 ;;
    --cpu-type) CPU_TYPE="$2"; shift 2 ;;
    --iso-url) ISO_URL="$2"; shift 2 ;;
    --iso-path) ISO_PATH="$2"; shift 2 ;;
    --latest) LATEST=true; shift ;;
    --dhcp) USE_DHCP=true; shift ;;
    --ip) IP_ADDR="$2"; USE_DHCP=false; shift 2 ;;
    --gw) GW_ADDR="$2"; shift 2 ;;
    --dns) DNS_SERVERS="$2"; shift 2 ;;
    --dns-search) DNS_SEARCH="$2"; shift 2 ;;
    --ci-user) CI_USER="$2"; shift 2 ;;
    --ci-pass) CI_PASSWORD="$2"; shift 2 ;;
    --ssh-pubkey) SSH_PUBKEY_PATH="$2"; shift 2 ;;
    --profile) TPOT_PROFILE="$2"; shift 2 ;;
    --enable-qga) ENABLE_QGA=true; shift ;;
    --start) START_VM=true; shift ;;
    --wait-cloudinit) WAIT_CLOUDINIT=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Option inconnue: $1"; usage; exit 1 ;;
  esac
done

# Pré-checks
if [[ $(id -u) -ne 0 ]]; then
  log_err "Exécuter ce script en root sur un nœud Proxmox."; exit 1
fi
for cmd in qm pvesm curl jq qemu-img; do
  command -v "$cmd" >/dev/null 2>&1 || { log_err "$cmd introuvable"; exit 1; }
done

# Auto-détection du bridge si demandé introuvable
AVAILABLE_BRIDGES=$(ls /sys/class/net 2>/dev/null | grep -E '^vmbr[0-9]+' | sort || true)
if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
  if [[ -n "${AVAILABLE_BRIDGES}" ]]; then
    FALLBACK_BRIDGE=$(echo "${AVAILABLE_BRIDGES}" | head -n1)
    if [[ -n "${BRIDGE}" ]]; then
      log_warn "Le bridge '${BRIDGE}' n'existe pas. Bascule automatique sur '${FALLBACK_BRIDGE}'."
    else
      log_info "Bridge par défaut introuvable. Auto-détection: utilisation de '${FALLBACK_BRIDGE}'."
    fi
    BRIDGE="${FALLBACK_BRIDGE}"
  fi
fi
if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
  log_err "Aucun bridge réseau valide détecté (vmbr*). Créez un bridge (ex: vmbr0) et réessayez."
  exit 1
fi

# VMID auto si nécessaire
if [[ -z "${VMID}" ]]; then
  log_info "Aucun VMID fourni: sélection automatique du premier ID libre"
  VMID=$(get_next_vmid)
  log_ok "VMID sélectionné: ${VMID}"
fi

# Vérifier stockages
pvesm status | awk 'NR>1{print $1}' | grep -qx "${STORAGE}" || { log_err "Storage --storage='${STORAGE}' introuvable"; exit 1; }
pvesm status | awk 'NR>1{print $1}' | grep -qx "${ISO_STORAGE}" || { log_err "Storage --iso-storage='${ISO_STORAGE}' introuvable"; exit 1; }

# Branche selon le mode
case "${MODE}" in
  debian13)
    # Provision Debian 13 via cloud-init
    ensure_snippets_local
    mkdir -p "${WORKDIR}"
    IMAGE_PATH="${WORKDIR}/debian-13.img"

    if [[ ! -f "${IMAGE_PATH}" ]]; then
      log_info "Téléchargement de l'image Debian 13 cloud (${DEBIAN_IMAGE_URL})"
      curl -fL "${DEBIAN_IMAGE_URL}" -o "${IMAGE_PATH}"
      log_ok "Image Debian téléchargée: ${IMAGE_PATH}"
    else
      log_info "Image Debian trouvée en cache: ${IMAGE_PATH}"
    fi

    # Création de la VM
    NETCONF="virtio,bridge=${BRIDGE}"
    if [[ -n "${VLAN_TAG}" ]]; then NETCONF+=",tag=${VLAN_TAG}"; fi

    log_info "Création de la VM ${VMID} (${NAME}) Debian 13"
    qm create "${VMID}" \
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
    qm importdisk "${VMID}" "${IMAGE_PATH}" "${STORAGE}" --format qcow2
    qm set "${VMID}" --scsi0 "${STORAGE}:vm-${VMID}-disk-0"
    qm set "${VMID}" --boot order=scsi0
    qm set "${VMID}" --ide2 "${STORAGE}:cloudinit"

    # QGA optionnel (recommandé)
    if [[ "${ENABLE_QGA}" == true ]]; then
      qm set "${VMID}" --agent enabled=1,fstrim_cloned_disks=1
    fi

    # Snippet cloud-init user-data
    SNIPPET_DIR="/var/lib/vz/snippets"
    mkdir -p "${SNIPPET_DIR}"
    USER_SNIPPET_PATH="${SNIPPET_DIR}/tpot-debian13-${VMID}-user.yaml"

    SSHKEYS_CONTENT=""
    if [[ -n "${SSH_PUBKEY_PATH}" ]]; then
      if [[ ! -f "${SSH_PUBKEY_PATH}" ]]; then
        log_err "Fichier clé publique introuvable: ${SSH_PUBKEY_PATH}"; exit 1
      fi
      SSHKEYS_CONTENT=$(cat "${SSH_PUBKEY_PATH}")
    fi

    IPCONFIG="ip=dhcp"
    if [[ "${USE_DHCP}" == false ]]; then
      if [[ -z "${IP_ADDR}" || -z "${GW_ADDR}" ]]; then
        log_err "IP statique requiert --ip et --gw"; exit 1
      fi
      IPCONFIG="ip=${IP_ADDR},gw=${GW_ADDR}"
    fi

    cat > "${USER_SNIPPET_PATH}" <<EOF2
#cloud-config
preserve_hostname: false
hostname: ${NAME}
manage_etc_hosts: true

locale: fr_CH.UTF-8
keyboard:
  layout: ch
  variant: fr
timezone: Europe/Zurich

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
  - [ bash, -lc, "systemctl daemon-reload || true" ]
  - [ bash, -lc, "systemctl enable --now tpot-bootstrap.service || true" ]

write_files:
  - path: /etc/motd
    permissions: '0644'
    content: |
      Système Debian 13 provisionné automatiquement (FR, clavier CH). T-Pot CE en cours d'installation.

  - path: /usr/local/sbin/tpot-bootstrap.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      LOG="/home/${CI_USER}/tpot-install.log"
      echo "[tpot-bootstrap] start $(date)" >>"${LOG}"
      cd "/home/${CI_USER}"
      if [ ! -d "tpotce" ]; then
        git clone https://github.com/telekom-security/tpotce tpotce >>"${LOG}" 2>&1 || true
      fi
      (cd tpotce && git pull --rebase >>"${LOG}" 2>&1) || true
      echo "[tpot-bootstrap] running installer (profile=${TPOT_PROFILE})" >>"${LOG}"
      export TPOT_PROFILE="${TPOT_PROFILE}"
      sudo -u ${CI_USER} bash -lc "TPOT_PROFILE=${TPOT_PROFILE} ~/tpotce/install.sh" >>"${LOG}" 2>&1 || true
      echo "[tpot-bootstrap] done $(date)" >>"${LOG}"

  - path: /etc/systemd/system/tpot-bootstrap.service
    permissions: '0644'
    content: |
      [Unit]
      Description=T-Pot CE Bootstrap Installer (Debian 13)
      Wants=network-online.target
      After=network-online.target

      [Service]
      Type=simple
      User=${CI_USER}
      WorkingDirectory=/home/${CI_USER}
      ExecStart=/usr/local/sbin/tpot-bootstrap.sh
      Restart=on-failure
      RestartSec=30s

      [Install]
      WantedBy=multi-user.target

final_message: "Cloud-init terminé pour ${NAME}. L'installation T-Pot CE est gérée par 'tpot-bootstrap.service'. Voir /home/${CI_USER}/tpot-install.log."
EOF2

    # Appliquer DNS / user / ssh / cicustom / ipconfig
    if [[ -n "${DNS_SERVERS}" ]]; then
      qm set "${VMID}" --nameserver "${DNS_SERVERS}" >/dev/null
    fi
    if [[ -n "${DNS_SEARCH}" ]]; then
      qm set "${VMID}" --searchdomain "${DNS_SEARCH}" >/dev/null
    fi
    qm set "${VMID}" --ciuser "${CI_USER}" >/dev/null
    if [[ -n "${CI_PASSWORD}" ]]; then
      qm set "${VMID}" --cipassword "${CI_PASSWORD}" >/dev/null
    fi
    if [[ -n "${SSHKEYS_CONTENT}" ]]; then
      qm set "${VMID}" --sshkeys "${SSH_PUBKEY_PATH}" >/dev/null
    fi
    qm set "${VMID}" --cicustom "user=local:snippets/$(basename "${USER_SNIPPET_PATH}")" >/dev/null
    qm set "${VMID}" --ipconfig0 "${IPCONFIG}" >/dev/null

    # Sauvegarde configuration et lancement optionnel
    CFG_OUT="./tpot_vm_${VMID}.conf"
    qm config "${VMID}" > "${CFG_OUT}"
    log_ok "Configuration de la VM sauvegardée: ${CFG_OUT}"

    if [[ "${START_VM}" == true ]]; then
      qm start "${VMID}"
      log_ok "VM ${VMID} démarrée. Debian 13 s'initialise via cloud-init."
      if [[ "${WAIT_CLOUDINIT}" == true && "${ENABLE_QGA}" == true ]]; then
        log_info "Attente de l'agent QEMU (QGA) jusqu'à 300s"
        for i in $(seq 1 60); do
          if qm agent "${VMID}" ping >/dev/null 2>&1; then
            log_ok "QGA disponible. Cloud-init est en cours/terminé."
            break
          fi
          sleep 5
        done
      fi
    else
      log_info "VM créée. Démarrez-la avec 'qm start ${VMID}'."
    fi

    cat <<EOT2

Prochaines étapes (mode Debian 13):
- Démarrer la VM si non démarrée: qm start ${VMID}
- Suivi cloud-init: journalctl -u cloud-init -n 200 --no-pager (dans la VM)
- Suivi T-Pot: systemctl status tpot (dans la VM) et /home/${CI_USER}/tpot-install.log

EOT2

    exit 0
    ;;
  iso)
    : # on poursuit le flot ISO ci-dessous
    ;;
  *)
    log_err "Mode inconnu: ${MODE} (attendu: iso|debian13)"; exit 1 ;;
esac

# ---------- MODE ISO (comportement existant) ----------

# Préparer chemin ISO sur le stockage choisi
ISO_ROOT=$(pve_storage_path "${ISO_STORAGE}")
if [[ -z "${ISO_ROOT}" ]]; then log_err "Impossible de déterminer le chemin du stockage ISO ${ISO_STORAGE}"; exit 1; fi
ISO_DIR="${ISO_ROOT}/template/iso"
mkdir -p "${ISO_DIR}"

# Obtenir le fichier ISO
if [[ -n "${ISO_PATH}" ]]; then
  if [[ ! -f "${ISO_PATH}" ]]; then log_err "ISO introuvable: ${ISO_PATH}"; exit 1; fi
  TARGET_ISO="${ISO_DIR}/$(basename "${ISO_PATH}")"
  if [[ "${ISO_PATH}" != "${TARGET_ISO}" ]]; then
    log_info "Copie de l'ISO vers ${TARGET_ISO}"
    cp -f "${ISO_PATH}" "${TARGET_ISO}"
  else
    log_info "ISO déjà présent sur le stockage: ${TARGET_ISO}"
  fi
elif [[ -n "${ISO_URL}" || "${LATEST}" == true ]]; then
  if [[ -z "${ISO_URL}" && "${LATEST}" == true ]]; then
    log_info "Résolution de la dernière ISO T-Pot depuis GitHub (releases/latest)"
    ISO_URL=$(resolve_latest_iso_url)
    log_ok "Dernière ISO détectée: ${ISO_URL}"
  fi
  FNAME=$(basename "${ISO_URL}")
  TARGET_ISO="${ISO_DIR}/${FNAME}"
  if [[ -f "${TARGET_ISO}" ]]; then
    log_info "ISO déjà présent: ${TARGET_ISO}"
  else
    log_info "Téléchargement de l'ISO T-Pot depuis ${ISO_URL}"
    curl -fL "${ISO_URL}" -o "${TARGET_ISO}"
    log_ok "ISO téléchargé: ${TARGET_ISO}"
  fi
else
  log_err "Veuillez fournir --iso-url, --iso-path ou --latest (voir le lien officiel pour l'URL de l'ISO)."; exit 1
fi

# Construire config réseau
NETCONF="virtio,bridge=${BRIDGE}"
if [[ -n "${VLAN_TAG}" ]]; then NETCONF+",tag=${VLAN_TAG}"; fi

# Créer la VM
log_info "Création de la VM ${VMID} (${NAME}) depuis ISO"
qm create "${VMID}" \
  --name "${NAME}" \
  --memory "${MEMORY_MB}" \
  --cores "${CORES}" \
  --cpu "${CPU_TYPE}" \
  --net0 "${NETCONF}" \
  --ostype l26 \
  --scsihw virtio-scsi-pci \
  --serial0 socket \
  --vga std

# Disque système
qm set "${VMID}" --scsi0 "${STORAGE}:0,cache=writeback,ssd=1"
qm set "${VMID}" --scsi0 "${STORAGE}:size=${DISK_SIZE}"

# Lecteur CDROM ISO
ISO_BASENAME=$(basename "${TARGET_ISO}")
qm set "${VMID}" --ide2 "${ISO_STORAGE}:iso/${ISO_BASENAME},media=cdrom"

# Boot order: disque d'abord, mais booter sur le CD la première fois si besoin depuis l'UI
qm set "${VMID}" --boot order=scsi0

# QGA optionnel
if [[ "${ENABLE_QGA}" == true ]]; then
  qm set "${VMID}" --agent enabled=1,fstrim_cloned_disks=1
fi

# Sauvegarde de la configuration pour référence
CFG_OUT="./tpot_vm_${VMID}.conf"
qm config "${VMID}" > "${CFG_OUT}"
log_ok "Configuration de la VM sauvegardée: ${CFG_OUT}"

# Démarrer si demandé
if [[ "${START_VM}" == true ]]; then
  qm start "${VMID}"
  log_ok "VM ${VMID} démarrée. Ouvrez la console et suivez l'installateur T-Pot depuis l'ISO."
else
  log_info "VM créée. Attachez-vous à la console pour lancer l'installation T-Pot depuis l'ISO."
fi

cat <<EOT

Prochaines étapes:
- Ouvrir la console Proxmox (VGA) de la VM ${VMID}
- Suivre l'installateur T-Pot à l'écran (depuis l'ISO ${ISO_BASENAME})
- Une fois installé, vous pourrez éjecter le CDROM et booter sur le disque (${DISK_SIZE})

Rappels:
- L'ISO provient du lien officiel: https://github.security.telekom.com/2022/04/honeypot-tpot-22.04-released.html#download-iso-image
- Pour changer l'ISO, relancez avec --iso-url ou --iso-path

EOT
