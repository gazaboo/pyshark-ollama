# Analyse de Paquets Réseau avec PyShark et Ollama

Ce projet capture paquets réseau en temps réel à l'aide de **PyShark**. 
Ces paquets sont  localisés géographiquement grâce à l'API **ipinfo.io** 
**Ollama** est utilisé pour faire appel à un LLM local (llama3.1) et générer un rapport d'analyse sur les paquets capturés sur le réseau. 

## Prérequis

Avant de démarrer, assurez-vous d'avoir installé les dépendances suivantes :

- **Python 3.11+**
- **PyShark** : Pour la capture de paquets réseau.
- **Requests** : Pour interagir avec l'API ipinfo.io.
- **Ollama** : Pour faire appel au LLM local ( LLAMA3.1 dans notre cas ).
- **ipaddress** : Pour la gestion des adresses IP.
- **pprint** : Pour un affichage plus joli des données.

Vous pouvez installer ces dépendances avec la commande suivante :

```bash
pip install pyshark requests ollama ipaddress pprint
``` 

## Configuration de Ollama 
Si vous voulez tester ollama dans la console, suivre les instructions ici : https://ollama.com/download

## Configuration du projet
J'ai écrit le code en Linux, mon interface réseau wifi est `wlp1s0`.

```python
capture = pyshark.LiveCapture(interface='wlp1s0')
```

Remplacez `wlp1s0` par le nom de l'interface réseau appropriée sur votre machine. Je ne connais pas le nom sur Windows et MacOS.

## Exécution du script
Pour exécuter le script il faut faire attention vérifiez si vous avez ou non besoin des droits  administrateur. Dans mon cas sur Linux j'utilise sudo devant la commande. 

En fonction de la manière dont votre python est configuré la commande sera différente. Dans mon cas j'utilise Anaconda. Si vous installez tout dans l'environnement `(base)` alors vous pouvez utiliser : 

 ```bash
 sudo ~/anaconda3/bin/python3 script.py
 ```
 ou bien si vous créez un environnement virtuel pour le projet : 

 ```bash
 sudo ~/anaconda3/envs/<ollama-env>/bin/python3 script.py
 ```
**Note :** je fais appel à l'exécutable python de cette manière là car je dois utiliser `sudo`, ce qui modifie le python appelé par défaut (même quand l'environnement virtuel est activé).

**ATTENTION :** la première exécution du script sera **très** longue, car il faut télécharger le modèle LLAMA3.1.

   

## LLM local 
Voici le prompt utilisé pour faire appel à Ollama : 

>You are a senior cybersecurity expert with deep knowledge of network protocols, network traffic analysis, and cybersecurity threats. Your task is to analyze network packets captured from a live network. Identify and explain any suspicious activity or anomalies, such as unusual IP addresses, abnormal traffic patterns, or known malicious behaviors. Provide a security assessment of the packet, indicating whether it seems benign, suspicious, or potentially malicious. Suggest possible threats or attack vectors that could be associated with the packet (e.g., DDoS, phishing, malware, port scanning, etc.). Recommend mitigation strategies or next steps for further investigation, if necessary.

J'ai remarqué en l'utilisant qu'il est très parano. Mais c'est peut être intéressant de comparer l'analyse de Ollama avec celle de vos étudiants. 
