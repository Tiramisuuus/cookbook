# Challenge 1 — VibeStream
## Analyse Externe & Détection de Signaux Cyber

### Contexte
Dans le domaine de la cybersécurité moderne, la capacité à analyser rapidement un site web, identifier des signaux faibles et détecter des comportements anormaux est essentielle.  
Ce challenge simule une mission d’analyste cyber : comprendre un environnement externe, collecter les bons indicateurs et formuler des hypothèses pertinentes.

### Objectif du Challenge
Réaliser un scan externe complet d’un site web (sans accès interne, sans score) afin de :
- collecter les données techniques essentielles,
- identifier des signaux faibles et forts,
- formuler des hypothèses sur d’éventuels risques ou comportements atypiques.

### Tâches Attendues
#### 1. Collecte & Ingestion
- Récupération du HTML, headers, certificat TLS, redirections, SSL.
- Extraction WHOIS : dates clés, registrar, durée de vie du domaine.

#### 2. Analyse & Détection
- Certificat faible ou expirant  
- Redirection anormale  
- Taille HTML anormale  
- Absence de HTTPS  
- Technologies obsolètes  
- Détection de signaux faibles

#### 3. Hypothèses & Interprétation
- Explication simple : “Ce signal pourrait indiquer X”
- Analyse contextualisée : impact, sévérité, probabilité

#### Optionnel
- Envoi des résultats vers une API externe  
- Mini‑pipeline (fetch → parse → analyse → synthèse)

### Critères de Réussite
- Détection d’au moins une anomalie non triviale  
- Justification claire  
- Proposition d’une amélioration ou nouvelle feature  
- Rapport final professionnel

### Livrables
- API de collecte et analyse de données  
- Dataset minimal  
- Page d’audit claire

### Bonus
- Détection d’un signal faible avant qu’il ne devienne critique  
- Optimisations (cache WHOIS, perf)  
- Visualisation (timeline, tableau)
