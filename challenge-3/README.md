# Challenge 3 — DarkWatch
## Analyse de Menaces OSINT (Threat Intelligence)

### Description
Le participant fournit un **nom de domaine**.  
Votre mission : conduire une **analyse OSINT complète** pour identifier signaux de menace, fuites, expositions, discussions suspectes publiques — **sans Dark Web réel**, uniquement des sources légales.

### Objectifs
- Collecter des données publiques sur le domaine  
- Rechercher mentions dans :
  - anciennes fuites anonymisées  
  - posts publics (forums, pastebins)  
  - blogs cyber  
  - rapports chercheurs  
  - Twitter/X, Reddit  
- Extraire entités sensibles : emails, IP, sous-domaines, tokens  
- Évaluer le risque : faible → critique  
- Générer un rapport professionnel

### Sources OSINT
- CERT-FR, CISA, ENISA  
- Rapid7, Qualys, Tenable, CheckPoint  
- BleepingComputer  
- Pastebin public  
- Tweets / articles cyber  
- HIBP (emails publics uniquement)

### Recherches Recommandées
- "domaine.com leak"  
- "domaine.com breach"  
- "domaine.com password"  
- "domaine.com data leak"  
- filetype:txt + email patterns

### Analyse attendue (exemples)
- 2 emails trouvés dans vieilles fuites → risque faible/moyen  
- API Key trouvée dans repo public → risque élevé  
- Aucune mention APT → menace faible active

### Livrables
- `osint_collector.py`  
- `osint_analyzer.py`  
- `report.md`  
