# Provision T-Pot via ISO sur Proxmox (PVE)

Ce document explique comment utiliser le script `tpot_iso_provision.sh` pour déployer une VM Proxmox démarrant sur l'ISO officiel T‑Pot, tel qu'indiqué par l'annonce: 

- https://github.security.telekom.com/2022/04/honeypot-tpot-22.04-released.html#download-iso-image

Le script prend en charge:
- Téléchargement (ou utilisation) de l'ISO T‑Pot sur le stockage ISO Proxmox.
- Création d'une VM PVE prête à démarrer sur l'ISO (console VGA standard).
- Auto‑détection du bridge réseau `vmbr*` si le bridge demandé n'existe pas.
- Sauvegarde de la configuration de la VM dans `tpot_vm_<VMID>.conf`.
 - Option `--latest` pour récupérer automatiquement la dernière ISO via l'API GitHub.

## Prérequis
- Exécuter sur le nœud Proxmox en root.
- Outils PVE disponibles: `qm`, `pvesm`, `curl`.
- Un stockage disque (ex: `local-lvm`) et un stockage ISO (ex: `local`).

## Paramètres clés
- `--vmid <ID>`: VMID (auto si omis).
- `--name <nom>`: nom de VM (défaut: `tpot-iso`).
- `--storage <storage>`: stockage disque VM (défaut: `local-lvm`).
- `--iso-storage <storage>`: stockage ISO (défaut: `local`).
- `--bridge <vmbrX>`: bridge réseau (défaut: `vmbr0`). Auto‑fallback sur premier `vmbr*` existant si introuvable.
- `--vlan <tag>`: VLAN optionnel.
- `--disk <taille>`: taille du disque (défaut: `256G`).
- `--memory <MB>`: RAM (défaut: `16384`).
- `--cores <N>`: vCPU (défaut: `4`).
- `--cpu-type <type>`: type CPU (défaut: `x86-64-v2-AES`).
- `--iso-url <url>`: URL de l'ISO T‑Pot (voir page officielle).
- `--iso-path <path>`: chemin local vers un ISO déjà téléchargé.
- `--enable-qga`: active le QEMU Guest Agent dans la VM (optionnel).
- `--start`: démarre la VM automatiquement à la fin.

## Exemple d'utilisation locale (avec URL ISO)
Remplacer `<version>` par la release souhaitée. Exemple de structure d'URL (à confirmer sur la page officielle):
```
https://github.com/telekom-security/tpotce/releases/download/<version>/T-Pot-<version>.iso
```

Commande:
```bash
chmod +x ./tpot_iso_provision.sh
./tpot_iso_provision.sh \
  --name tpot-iso \
  --storage local-lvm \
  --iso-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --iso-url "https://github.com/telekom-security/tpotce/releases/download/<version>/T-Pot-<version>.iso" \
  --start
```

## Exemple d'utilisation locale (avec ISO local)
```bash
chmod +x ./tpot_iso_provision.sh
./tpot_iso_provision.sh \
  --name tpot-iso \
  --storage local-lvm \
  --iso-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --iso-path "/root/T-Pot-<version>.iso" \
  --start
```

## Exécution directe depuis GitHub (sdavid66)
Depuis le nœud Proxmox (root), exécuter le script directement via `raw.githubusercontent.com`:

- Avec URL ISO:
```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/tpot_iso_provision.sh?nocache=$(date +%s)") \
  --name tpot-iso \
  --storage local-lvm \
  --iso-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --iso-url "https://github.com/telekom-security/tpotce/releases/download/<version>/T-Pot-<version>.iso" \
  --start
```

- Avec résolution automatique de la dernière ISO (`--latest`) — nécessite `jq`:
```bash
apt-get update && apt-get install -y jq
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/tpot_iso_provision.sh?nocache=$(date +%s)") \
  --name tpot-iso \
  --storage local-lvm \
  --iso-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --latest \
  --start
```

- Avec ISO local (déjà présent sur le nœud):
```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Sdavid66/proxmox-honeypot/main/tpot_iso_provision.sh?nocache=$(date +%s)") \
  --name tpot-iso \
  --storage local-lvm \
  --iso-storage local \
  --bridge vmbr0 \
  --disk 256G \
  --memory 16384 \
  --cores 4 \
  --iso-path "/root/T-Pot-<version>.iso" \
  --start
```

## Après création
- Ouvrir la console Proxmox (VGA) de la VM et suivre l’installateur T‑Pot.
- Une fois l’installation terminée, éjecter l’ISO (ou ajuster l’ordre de boot) pour démarrer sur le disque.
- La configuration de la VM a été sauvegardée dans un fichier `tpot_vm_<VMID>.conf` à la racine du dépôt (si vous avez exécuté le script depuis ce répertoire).

## Notes et bonnes pratiques
- L’auto‑détection de bridge choisira le premier `vmbr*` disponible si celui demandé n’existe pas.
- Si vous utilisez un VLAN, ajoutez `--vlan <tag>`.
- Vérifiez la somme SHA256 de l’ISO si le projet la publie (sécurité d’approvisionnement).
- Ressources minimales recommandées pour T‑Pot (selon profil) peuvent être élevées; ajustez `--memory` et `--disk` en conséquence.
