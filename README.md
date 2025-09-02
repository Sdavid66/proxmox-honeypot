# Proxmox Honeypot (T-Pot CE) – Provision Script

Ce projet fournit un script Bash pour créer automatiquement une VM Ubuntu 22.04 (cloud) sur Proxmox (PVE) configurée via cloud-init et installant [T-Pot CE](https://github.com/telekom-security/tpotce) depuis le dépôt GitHub au premier démarrage.

## Prérequis

- S'exécute directement sur le nœud Proxmox, en root (ex: `root@pve`).
- Proxmox PVE avec les outils: `qm`, `pvesm`, `curl`, `qemu-img`.
- Un stockage pour disques VM (ex: `local-lvm`).
- Un stockage supportant les snippets (contenu « Snippets » activé), souvent `local`.
  - Dans l'UI: Datacenter → Storage → (votre storage) → Content → cocher « Snippets ».
- Accès Internet depuis le nœud PVE pour télécharger l'image cloud Ubuntu et le dépôt T-Pot CE.
- Note: le script activera automatiquement le contenu « snippets » sur le stockage `local` si nécessaire.

## Fichiers

- `provision_honeypot_vm.sh`: script de provisioning principal.

## Installation locale (optionnelle)

Copiez les fichiers sur votre nœud PVE (ou clonez ce dossier) puis rendez le script exécutable:

```bash
chmod +x provision_honeypot_vm.sh
```

## Utilisation

Par défaut:

- VMID est auto-sélectionné (premier ID libre dans Proxmox). Vous pouvez toujours forcer via `--vmid <ID>`.
- Si aucune IP n'est fournie, la VM utilisera DHCP. Si QGA est activé, le script tentera d'afficher l'IP détectée après démarrage.
 - Bridge réseau: si `--bridge` est omis ou invalide, le script sélectionne automatiquement le premier bridge disponible (`vmbr*`, ex: `vmbr0`).

Note importante (taille disque et image cache):

- Si une image cache existe déjà sur le nœud (ex: `/tmp/pve-honeypot-build/ubuntu-22.04.img`) et qu'elle est plus grande que votre cible, spécifiez `--disk` avec une taille ≥ à l'image existante (ex: `--disk 256G`).
- Alternative: supprimez l'image cache puis relancez à la taille désirée (défaut 64G):

```bash
rm -f /tmp/pve-honeypot-build/ubuntu-22.04.img
```

Exemple profil Hive (IP statique) avec démarrage auto et attente cloud-init:

```bash
./provision_honeypot_vm.sh \
  --vmid 9001 \
  --name tpot-ubuntu22 \
  --storage local-lvm \
  --bridge vmbr0 \
  --vlan 30 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --ip 192.168.30.50/24 \
  --gw 192.168.30.1 \
  --dns "1.1.1.1 8.8.8.8" \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --profile hive \
  --start \
  --wait-cloudinit
```

Exemple profil Sensor en DHCP (VMID auto):

```bash
./provision_honeypot_vm.sh \
  --name tpot-sensor \
  --storage local-lvm \
  --bridge vmbr0 \
  --disk 128G \
  --memory 8192 \
  --dhcp \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --profile sensor \
  --start \
  --wait-cloudinit
```

## Exécution directe depuis GitHub

Depuis un shell sur le nœud Proxmox (root), vous pouvez exécuter le script directement depuis le dépôt GitHub.

Exemple IP statique (profil Hive):

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/provision_honeypot_vm.sh?nocache=$(date +%s)") \
  --vmid 9001 \
  --name tpot-ubuntu22 \
  --storage local-lvm \
  --bridge vmbr0 \
  --vlan 30 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --ip 192.168.30.50/24 \
  --gw 192.168.30.1 \
  --dns "1.1.1.1 8.8.8.8" \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --profile hive \
  --start \
  --wait-cloudinit
```

Exemple DHCP (profil Sensor, VMID auto):

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/provision_honeypot_vm.sh?nocache=$(date +%s)") \
  --name tpot-sensor \
  --storage local-lvm \
  --bridge vmbr0 \
  --disk 128G \
  --memory 8192 \
  --dhcp \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --profile sensor \
  --start \
  --wait-cloudinit
```

Exemple DHCP avec image cache existante (spécifie `--disk 256G` par ex. pour Hive):

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/provision_honeypot_vm.sh?nocache=$(date +%s)") \
  --name tpot-ubuntu22 \
  --storage local-lvm \
  --ci-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --dhcp \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --profile hive \
  --start \
  --wait-cloudinit
```

Paramètres principaux:

- `--vmid <ID>`: ID VM unique (optionnel; auto si omis).
- `--name <nom>`: nom de la VM (défaut: `tpot-ubuntu22`).
- `--storage <storage>`: stockage disque (défaut: `local-lvm`).
- `--ci-storage <storage>`: (forcé à `local` pour les snippets).
- `--bridge <vmbrX>`: bridge réseau (défaut: `vmbr0`).
- `--vlan <tag>`: Tag VLAN (optionnel).
- `--disk <taille>`: taille disque (défaut: `64G`).
- `--memory <MB>`: RAM (défaut: `8192`).
- `--cores <N>`: vCPU (défaut: `1`).
- `--cpu-type <type>`: Type CPU (défaut: `x86-64-v2-AES`).
- `--dhcp` ou `--ip <CIDR>` + `--gw <IP>`.
- `--dns "IP [IP...]"` et `--dns-search <domain>`.
- `--ci-user`, `--ci-pass`, `--ssh-pubkey <path>`.
- `--profile <hive|sensor>`: profil T-Pot (défaut: `hive`).
- `--force`: ignorer les vérifications minimales de ressources.
- `--no-qga`, `--start`, `--wait-cloudinit`.

## Dépannage

### Erreur: qemu-img demande `--shrink`

Symptômes:

```
qemu-img: Use the --shrink option to perform a shrink operation.
qemu-img: warning: Shrinking an image will delete all data beyond the shrunken image's end.
```

Causes possibles:

- L'image cache `qcow2` existe déjà sur le nœud (ex: `/tmp/pve-honeypot-build/ubuntu-22.04.img`) avec une taille virtuelle supérieure à la cible (ex: cache à 256G, cible à 64G).

Solutions (choisir l'une des deux):

- Option B (recommandée sur ancienne image cache): spécifier une taille disque supérieure ou égale à la taille actuelle de l'image cache, par ex. `--disk 256G`.
- Ou supprimer l'image cache puis relancer à 64G:
```bash
rm -f /tmp/pve-honeypot-build/ubuntu-22.04.img
```

Note:

- Le script supporte un mode « grow-only » par défaut. Si une réduction est explicitement souhaitée, utilisez `--allow-shrink` (opération destructive, à éviter en production).

- Réseau: `--dhcp` ou `--ip <CIDR>` + `--gw <IP>`.
- DNS: `--dns "IP [IP...]"` et `--dns-search <domain>`.
- Cloud-init user: `--ci-user`, `--ci-pass`, `--ssh-pubkey <path>`.
- `--no-qga` pour désactiver qemu-guest-agent.
 - `--start` pour démarrer automatiquement la VM à la fin du script.
 - `--wait-cloudinit` pour attendre la disponibilité de l'agent QEMU et indiquer l'état cloud-init (si QGA activé).

## Ce que fait le script

- Télécharge l'image Ubuntu 22.04 cloud (qcow2) et redimensionne selon `--disk`.
- Crée la VM (CPU, RAM, réseau, disque), ajoute le lecteur cloud-init.
- Active Qemu Guest Agent (optionnel, actif par défaut).
- Génère un snippet cloud-init `user-data` qui:
  - installe `sudo`, ajoute `${CI_USER}` au groupe sudo avec `NOPASSWD`,
  - clone `tpotce` et exécute `~/tpotce/install.sh` en tant que `${CI_USER}` avec `TPOT_PROFILE`.
- Configure réseau (DHCP ou IP statique), DNS, utilisateur cloud-init et clés SSH.
- Affiche un suivi d'exécution coloré (vert=OK, rouge=échec) pour chaque étape clé (création VM, import disque, configuration cloud-init, etc.).

## Démarrage et vérifications

Après exécution du script:

```bash
qm start <VMID>
qm terminal <VMID>
```

Dans la VM:

- Vérifier cloud-init: `journalctl -u cloud-init -n 200 --no-pager`
- Vérifier T-Pot: `systemctl status tpot`
- Consulter la documentation T-Pot CE pour l'accès WebUI et services.

## Sécurité et réseau

 - Placez cette VM sur un segment interne contrôlé (ex: `vmbr0`, VLAN dédié).
- Référez-vous aux ports requis par T-Pot CE dans sa documentation officielle.

## Suppression de la VM

```bash
qm stop <VMID> || true
qm destroy <VMID> --purge
```

## Licence

MIT
