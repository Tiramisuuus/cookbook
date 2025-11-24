# Challenge 2 — AppSleuth
## Analyse Comportementale d’Applications

### Contexte
Vous jouez le rôle d’un analyste cybersécurité chargé d’évaluer le comportement d’une application mobile.  
Objectif : comprendre ce qu’elle fait en arrière-plan (permissions, serveurs contactés, comportements suspects).

### Objectif du Challenge
- Recevoir des traces comportementales  
- Analyser les permissions, appels réseau, événements  
- Détecter signaux faibles, dérives, comportements anormaux  
- Construire une API de détection  
- Proposer une amélioration (règle, feature, signal)

### Types de Données Manipulées
1. **Permissions** : caméra, GPS, contacts, micro, stockage  
2. **Appels réseau** : endpoints, fréquence, volume, domaine  
3. **Événements** : ouverture app, capture photo, navigation  
4. **Métadonnées APK** : version, taille, SDK

### Ce qu’un analyste doit comprendre
- Permissions incohérentes  
- Envoi GPS après photo → signal faible  
- Appels réseau vers domaine inconnu → signal fort  

### Livrables
- API fonctionnelle d’analyse comportementale  
- Dataset minimal  
- Page d’audit claire  
