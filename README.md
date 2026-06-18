<img src="application.png" align="right"/>
<br>

Le tableau de bord offre une vision centralisée de l'état du système en combinant métriques système, analyse réseau et détection d'événements de sécurité dans une interface unique et intuitive.

🛡️ Dashboard de Surveillance et d'Évaluation des Risques Système

Cette interface fournit une vue d'ensemble en temps réel de l'état de sécurité d'un système. Elle centralise les informations essentielles liées aux processus, aux ports réseau, aux connexions actives et aux alertes de sécurité afin de faciliter la détection d'anomalies et l'analyse des risques.

- Fonctionnalités principales
- Vue d'ensemble du système

Le tableau de bord affiche instantanément les indicateurs clés :

Total Alerts : nombre total d'alertes détectées.
Risk Score : score global de risque calculé à partir des événements de sécurité.
Listening Ports : nombre de ports actuellement en écoute.
Processes : nombre de processus actifs.
Connections : nombre de connexions réseau détectées.
Threats Detected : menaces identifiées par les règles d'analyse.
CPU Usage : consommation processeur en temps réel.
Memory Usage : utilisation de la mémoire vive.
Disk Usage : occupation du stockage.

- Gestion des alertes de sécurité

Le module Security Alerts centralise les événements suspects détectés sur le système.

Chaque alerte contient :

Niveau de sévérité (Low, Medium, High, Critical)
Type d'événement
Description détaillée
Horodatage de détection

Exemples d'alertes :

Détection d'un port potentiellement dangereux exposé.
Service SMTP ouvert pouvant être utilisé comme relais de spam.
Désactivation du Secure Boot augmentant les risques de compromission.

Des filtres permettent d'afficher uniquement certaines catégories d'alertes.

- Évaluation du risque

Le panneau Risk Assessment présente :

Un score de risque global.
La répartition des alertes par niveau de criticité.
Une visualisation rapide de l'état de sécurité du système.

Cette vue permet d'identifier rapidement les points nécessitant une intervention prioritaire.

- Surveillance des ports réseau

Le module Listening Ports recense tous les ports ouverts du système avec :

Information	Description
Port	Numéro du port
Protocol	TCP/UDP
Process	Processus associé
PID	Identifiant du processus
User	Utilisateur propriétaire
Risk	Niveau de risque associé

Les ports sensibles sont automatiquement signalés afin de faciliter leur analyse.

- Analyse des connexions réseau

La section Network Connections affiche les connexions actives et les sockets en écoute :

Adresse locale
Adresse distante
Pays d'origine détecté
État de la connexion
Processus associé
PID du processus

Cette fonctionnalité permet de repérer rapidement des connexions inhabituelles ou potentiellement malveillantes.

- Interface utilisateur
Design moderne inspiré des outils SOC (Security Operations Center).
Thème sombre optimisé pour la surveillance continue.
Indicateurs colorés selon le niveau de criticité.
Mise à jour en temps réel des métriques système.
Navigation claire et lisible pour une analyse rapide.

- Cas d'utilisation
Surveillance de serveurs Linux.
Détection précoce d'activités suspectes.
Audit de sécurité système.
Monitoring réseau.
Environnement de laboratoire cybersécurité.
Démonstration et apprentissage de la sécurité offensive/défensive.





