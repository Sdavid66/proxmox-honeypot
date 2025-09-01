# Proxmox Honeypot (Cowrie) – Provision Script

Ce projet fournit un script Bash pour créer automatiquement une VM Debian 12 sur Proxmox (PVE) configurée via cloud-init et déployant le honeypot SSH Cowrie au premier démarrage.

## Prérequis

- S'exécute directement sur le nœud Proxmox, en root (ex: `root@pve`).
- Proxmox PVE avec les outils: `qm`, `pvesm`, `curl`, `qemu-img`.
- Un stockage pour disques VM (ex: `local-lvm`).
- Un stockage supportant les snippets (contenu « Snippets » activé), souvent `local`.
  - Dans l'UI: Datacenter → Storage → (votre storage) → Content → cocher « Snippets ».
- Accès Internet depuis le nœud PVE pour télécharger l'image cloud Debian et le repo de Cowrie.

## Fichiers

- `provision_honeypot_vm.sh`: script de provisioning principal.

## Installation

Copiez les fichiers sur votre nœud PVE (ou clonez ce dossier) puis rendez le script exécutable:

```bash
chmod +x provision_honeypot_vm.sh
```

## Utilisation

Par défaut:

- VMID est auto-sélectionné (premier ID libre dans Proxmox). Vous pouvez toujours forcer via `--vmid <ID>`.
- Si aucune IP n'est fournie, la VM utilisera DHCP. Si QGA est activé, le script tentera d'afficher l'IP détectée après démarrage.

Note importante (taille disque et image cache):

- Si une image cache existe déjà sur le nœud (ex: `/tmp/pve-honeypot-build/debian-12.qcow2`) et qu'elle est plus grande que votre cible, spécifiez `--disk` avec une taille ≥ à l'image existante (ex: `--disk 10G`).
- Alternative: supprimez l'image cache puis relancez à la taille désirée (par défaut 8G):

```bash
rm -f /tmp/pve-honeypot-build/debian-12.qcow2
```

Exemple complet (IP statique) avec démarrage auto et attente cloud-init:

```bash
./provision_honeypot_vm.sh \
  --vmid 9001 \
  --name hp-debian12 \
  --storage local-lvm \
  --ci-storage local \
  --bridge vmbr1 \
  --vlan 30 \
  --disk 10G \
  --memory 2048 \
  --cores 2 \
  --ip 192.168.30.50/24 \
  --gw 192.168.30.1 \
  --dns "1.1.1.1 8.8.8.8" \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --start \
  --wait-cloudinit
```

Exemple en DHCP (VMID auto, IP via DHCP auto):

```bash
./provision_honeypot_vm.sh \
  --name hp-dhcp \
  --storage local-lvm \
  --bridge vmbr1 \
  --dhcp \
  --ssh-pubkey /root/.ssh/id_rsa.pub
```

## Exécution directe depuis GitHub

Depuis un shell sur le nœud Proxmox (root), vous pouvez exécuter le script directement depuis le dépôt GitHub.

Exemple IP statique:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/provision_honeypot_vm.sh) \
  --vmid 9001 \
  --name hp-debian12 \
  --storage local-lvm \
  --ci-storage local \
  --bridge vmbr1 \
  --vlan 30 \
  --disk 10G \
  --memory 2048 \
  --cores 2 \
  --ip 192.168.30.50/24 \
  --gw 192.168.30.1 \
  --dns "1.1.1.1 8.8.8.8" \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --start \
  --wait-cloudinit
```

Exemple DHCP (VMID auto):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/provision_honeypot_vm.sh) \
  --name hp-dhcp \
  --storage local-lvm \
  --bridge vmbr1 \
  --dhcp \
  --ssh-pubkey /root/.ssh/id_rsa.pub \
  --start \
  --wait-cloudinit
```

Paramètres principaux:

- `--vmid <ID>`: ID VM unique (obligatoire).
- `--name <nom>`: nom de la VM (défaut: `honeypot-debian12`).
- `--storage <storage>`: stockage disque (défaut: `local-lvm`).
- `--ci-storage <storage>`: stockage avec « Snippets » activé (défaut: `local`).
- `--bridge <vmbrX>`: bridge réseau (défaut: `vmbr0`).
- `--vlan <tag>`: Tag VLAN (optionnel).
- `--disk <taille>`: taille disque (défaut: `8G`).
- `--memory <MB>`: RAM (défaut: `1024`).
- `--cores <N>`: vCPU (défaut: `1`).
- `--cpu-type <type>`: Type CPU (défaut: `x86-64-v2-AES`).

## Dépannage

### Erreur: qemu-img demande `--shrink`

Symptômes:

```
qemu-img: Use the --shrink option to perform a shrink operation.
qemu-img: warning: Shrinking an image will delete all data beyond the shrunken image's end.
```

Causes possibles:

- L'image cache `qcow2` existe déjà sur le nœud (ex: `/tmp/pve-honeypot-build/debian-12.qcow2`) avec une taille virtuelle supérieure à la cible (ex: cache à 10G, cible à 8G).

Solutions (choisir l'une des deux):

- Option B (recommandée sur ancienne image cache): spécifier une taille disque supérieure ou égale à la taille actuelle de l'image cache, par ex. `--disk 10G`.
- Ou supprimer l'image cache puis relancer à 8G:

```bash
rm -f /tmp/pve-honeypot-build/debian-12.qcow2
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

- Télécharge l'image Debian 12 cloud (qcow2) et redimensionne selon `--disk`.
- Crée la VM (CPU, RAM, réseau, disque), ajoute le lecteur cloud-init.
- Active Qemu Guest Agent (optionnel, actif par défaut).
- Génère un snippet cloud-init `user-data` installant et démarrant Cowrie comme service systemd.
- Configure réseau (DHCP ou IP statique), DNS, utilisateur cloud-init et clés SSH.
 - Déplace le SSH système sur le port `2222` (non exposé par UFW) pour éviter le conflit avec Cowrie sur `22`.
 - Applique une politique UFW finale: `deny outgoing` et `deny incoming` (sauf loopback). La VM ne peut plus initier de connexions sortantes.
 - Affiche un suivi d'exécution coloré (vert=OK, rouge=échec) pour chaque étape clé (création VM, import disque, configuration cloud-init, etc.).

## Démarrage et vérifications

Après exécution du script:

```bash
qm start <VMID>
qm terminal <VMID>
```

Dans la VM:

- Vérifier cloud-init: `journalctl -u cloud-init -n 200 --no-pager`
- Vérifier Cowrie: `systemctl status cowrie`
- Logs Cowrie: `/opt/cowrie/cowrie/var/log/cowrie/`

## Sécurité et réseau

- Placez cette VM sur un segment interne contrôlé (ex: `vmbr1`, VLAN dédié).
- UFW: tout trafic sortant est bloqué, seul le loopback est autorisé; trafic entrant par défaut bloqué.
- Cowrie écoute sur 22. Le SSH système est déplacé sur 2222 et n'est pas ouvert au pare-feu par défaut (accès via console Proxmox recommandé).

## Suppression de la VM

```bash
qm stop <VMID> || true
qm destroy <VMID> --purge
```

## Licence

MIT
