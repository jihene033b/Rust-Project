# Rust Security Tooling Suite

Suite d'outils de sécurité réseau écrite en Rust, organisée en workspace Cargo. Le projet regroupe un scanner de ports, un fuzzer HTTP et un scanner de CVE, tous pilotés depuis un seul binaire.

## Structure du projet

```
crates/
  network_scanner/     # Scanner de ports reseau (TCP, UDP, ping, bannières)
  http_fuzzer/         # Fuzzer HTTP par wordlist
  cve_scanner/         # Recherche de vulnérabilités CVE
  main_orchestrator/   # Binaire principal — expose les sous-commandes
```

## Prérequis

- Rust et Cargo installés (https://rustup.rs)
- Pour le scan UDP sur certains systèmes, des droits administrateur peuvent être nécessaires

## Compiler le projet

```bash
# mode développement
cargo build

# mode release (recommandé pour les performances)
cargo build --release
```

Le binaire compilé se trouve dans `target/release/scanner` (ou `target/debug/scanner` en mode dev).

## Lancer les outils

Toutes les commandes passent par `main_orchestrator`. Deux façons de lancer :

**Avec cargo (développement) :**

```bash
cargo run -p main_orchestrator -- <sous-commande> [options]
```

**Avec le binaire compilé (release) :**

```bash
./target/release/scanner <sous-commande> [options]
```

## Scanner reseau — sous-commande `scan`

Scan les ports ouverts d'une cible. Supporte les IPs simples, les plages CIDR et les intervalles d'adresses

### Options

| Option          | Description                                                                      |
| --------------- | -------------------------------------------------------------------------------- |
| `-t, --target`  | Cible : IP, CIDR (`192.168.1.0/24`) ou plage (`192.168.1.1-192.168.1.50`)        |
| `-p, --ports`   | Ports à scanner : `22`, `80,443`, `1-1024`                                       |
| `--top-ports N` | Scanner les N premiers ports de la liste Nmap top 1000                           |
| `-T 0..5`       | Niveau de timing : T0 (lent) à T5 (très rapide). T4 et T5 demandent confirmation |
| `--no-ping`     | Ne pas vérifier si l'hôte est vivant avant de scanner (comme Nmap `-Pn`)         |
| `--exclude`     | Exclure une IP, un CIDR ou une plage du scan                                     |
| `--sU`          | Scanner en UDP au lieu de TCP                                                    |
| `-o, --output`  | Enregistrer les résultats dans un fichier JSON                                   |

### Exemples

```bash
# scanner une IP sur les ports les plus courants
cargo run -p main_orchestrator -- scan -t 192.168.1.1 --top-ports 100

# scanner un réseau entier sans ping préalable
cargo run -p main_orchestrator -- scan -t 192.168.1.0/24 --no-ping --top-ports 1000

# scanner des ports specifiques avec export JSON
cargo run -p main_orchestrator -- scan -t 192.168.1.1 -p 22,80,443,8080 -o resultats.json

# scanner en UDP
cargo run -p main_orchestrator -- scan -t 192.168.1.1 --sU

# scanner rapidement avec le niveau T4
cargo run -p main_orchestrator -- scan -t 192.168.1.1 --top-ports 1000 -T 4

# exclure une machine du scan reseau
cargo run -p main_orchestrator -- scan -t 192.168.1.0/24 --exclude 192.168.1.1 --no-ping
```

### Etats de ports

- `open` : le port repond, une connexion a pu etre etablie
- `closed` : le port est fermé (la cible a répondu avec un refus)
- `filtered` : pas de réponse dans le délai imparti (firewall probable)
- `open|filtered` : en UDP uniquement, pas de réponse mais pas de refus non plus

### Format du JSON exporté

```json
[
  {
    "ip": "192.168.1.10",
    "open_ports": [
      {
        "port": 22,
        "state": "Open",
        "service": "ssh",
        "banner": "SSH-2.0-OpenSSH_9.0"
      },
      {
        "port": 80,
        "state": "Open",
        "service": "http",
        "banner": "HTTP/1.1 200 OK"
      }
    ],
    "closed_count": 997,
    "filtered_count": 1,
    "open_filtered_count": 0
  }
]
```

---

## Fuzzer HTTP — sous-commande `fuzz`

Teste une URL cible en envoyant des requêtes pour chaque mot d'une wordlist. Utile pour découvrir des chemins, fichiers ou répertoires exposés.

### Options

| Option               | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `-u, --url`          | URL cible (ex: `http://exemple.com`)                           |
| `-w, --wordlist`     | Chemin vers la wordlist                                        |
| `-t, --threads`      | Nombre de threads parallèles (défaut : 40)                     |
| `-s, --status-codes` | Codes HTTP à afficher (défaut : `200,204,301,302,307,401,403`) |
| `-x, --extensions`   | Extensions à tester en plus (ex: `php,html,txt`)               |
| `-a, --user-agent`   | User-Agent HTTP personnalisé                                   |
| `-v, --verbose`      | Afficher les erreurs de connexion                              |
| `-o, --output`       | Enregistrer les résultats dans un fichier JSON                 |

### Exemples

```bash
# fuzzer un site avec une wordlist
cargo run -p main_orchestrator -- fuzz -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# avec des extensions et export JSON
cargo run -p main_orchestrator -- fuzz -u http://192.168.1.10 -w wordlist.txt -x php,html -o rapport.json

# avec plus de threads et codes HTTP personnalisés
cargo run -p main_orchestrator -- fuzz -u http://192.168.1.10 -w wordlist.txt -t 100 -s 200,301,403
```

---

## Scanner de CVE — crate `cve_scanner`

Analyse une liste de services (nom + version) et cherche les vulnérabilités connues qui les affectent. Le scanner compare les services contre une base de données locale de CVE et peut aussi interroger l'API officielle NVD (National Vulnerability Database).

### Comment ca fonctionne

Le scanner prend en entrée un fichier JSON décrivant les services en cours sur une machine, puis retourne les CVE correspondantes avec leur score CVSS et leur niveau de sévérité.

### Format du fichier d'entrée

```json
{
  "services": [
    { "name": "Apache", "version": "2.4.41" },
    { "name": "OpenSSL", "version": "1.1.1g" },
    { "name": "nginx", "version": "1.18.0" }
  ]
}
```

### Options disponibles

| Option | Description |
|---|---|
| `input_file` | Fichier JSON contenant la liste des services (obligatoire) |
| `--output` | Fichier de sortie pour le rapport JSON |
| `--cache` | Dossier pour le cache local des CVE (défaut : `./cache`) |
| `--nvd` | Interroger l'API NVD en ligne au lieu des données locales |
| `--min-severity` | Filtrer par sévérité minimale : `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--min-cvss` | Filtrer par score CVSS minimum (ex: `7.5`) |

### Format du rapport de sortie

```json
{
  "scanned_services": [
    { "name": "Apache", "version": "2.4.41" }
  ],
  "vulnerabilities_found": [
    {
      "cve_id": "CVE-2021-41773",
      "service_name": "Apache",
      "affected_versions": ["2.4.49"],
      "description": "Path traversal and RCE vulnerability",
      "severity": "CRITICAL",
      "cvss_score": 9.8
    }
  ],
  "summary": "1 vulnerability found"
}
```

---

## Tester le projet

### Lancer tous les tests

```bash
cargo test
```

### Tester un crate specifique

```bash
cargo test -p network_scanner
cargo test -p http_fuzzer
cargo test -p cve_scanner
```

### Tests rapides sans réseau

Pour tester le scanner sans avoir besoin d'une cible externe, utiliser `127.0.0.1` avec `--no-ping` :

```bash
cargo run -p main_orchestrator -- scan -t 127.0.0.1 --no-ping -p 22,80,443,5000,7000,8080 -o test.json
```
