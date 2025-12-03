
## 1. Prérequis

- Python 3 installé
- Module Python `requests`
- Commande `whois`
- (Optionnel) Clé API Shodan

### Installation rapide (macOS / Linux)

```bash
# Vérifier Python 3
python3 --version

# Installer le module requests
python3 -m pip install --user requests

# Installer whois
# macOS (Homebrew) :
brew install whois

# Debian/Ubuntu :
# sudo apt update
# sudo apt install -y whois


⸻

2. Lancer la collecte OSINT

Dans le dossier contenant osint_collector.py :

Sans Shodan

python3 osint_collector.py \
  --domain exemple.com \
  --out resultat_simple.json

Avec Shodan

python3 osint_collector.py \
  --domain exemple.com \
  --shodan-key VOTRE_CLE_SHODAN \
  --out resultat_simple_shodan.json


⸻

3. Lancer l’analyse

À partir du fichier de collecte :

python3 osint_analyzer.py \
  --input resultat_simple_shodan.json \
  --out analysis_exemple.json


