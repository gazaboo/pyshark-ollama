import ollama
import pyshark
import requests
import ipaddress
import pprint

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_private_IP(ip):
    """On regarde si l'IP est privée (locale)"""
    return ipaddress.ip_address(ip).is_private

# Function to get the country of an IP address using ipinfo.io API
def get_geographic_info_from_IP(ip):
    """On récupère des infos sur l'IP via ipinfo.io (gratuit)"""
    
    if is_private_IP(ip):
        return {
            'ip': ip,
            'hostname': 'local machine',
        }
    
    try:
        # Fetch info from ipinfo.io for public IP
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'hostname': data.get('hostname', 'Not found'),
                'city': data.get('city', 'Not found'),
                'country': data.get('country', 'Not found')
            }
        else:
            logging.warning(f"Failed to fetch info for IP: {ip}. Status code: {response.status_code}")
            return {'ip': ip, 'error': 'Error fetching IP data'}
    
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching IP data for {ip}: {e}")
        return {'ip': ip, 'error': 'Error fetching IP data'}

def process_packet(packet):
    """Ajoute les infos de geolocalisation sur les packets grâce à leur IP"""
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Get info about the source and destination IPs
            source_info = get_geographic_info_from_IP(src_ip)
            destination_info = get_geographic_info_from_IP(dst_ip)

            # Structure the packet information
            packet_info = {
                'source': source_info,
                'destination': destination_info
            }
            return packet_info

    except AttributeError:
        logging.error("Packet does not have IP layer.")
        return None

def init_ollama_model(model_name):
    """ Creation d'un modele ollama. On lui donne un rôle. """
    model_list = list(map(lambda model: model['name'], ollama.list()['models']))
    
    # Je teste pour ne pas recréer inutilement deux fois le même modèle
    if f'{model_name}:latest' in model_ list:
        logging.info("Ollama model 'cybersec' exists")
        return
    
    # Création du modèle. On lui donne un rôle d'expert en cybersécurité. 
    # Le prompt est long mais ça bugge quand on le mets sur plusieurs lignes, faudrait rééssayer autrement
    try:
        modelfile = '''
        FROM llama3.1
        SYSTEM You are a senior cybersecurity expert with deep knowledge of network protocols, network traffic analysis, and cybersecurity threats. Your task is to analyze network packets captured from a live network. Identify and explain any suspicious activity or anomalies, such as unusual IP addresses, abnormal traffic patterns, or known malicious behaviors. Provide a security assessment of the packet, indicating whether it seems benign, suspicious, or potentially malicious. Suggest possible threats or attack vectors that could be associated with the packet (e.g., DDoS, phishing, malware, port scanning, etc.). Recommend mitigation strategies or next steps for further investigation, if necessary.
        '''
        ollama.create(model=model_name, modelfile=modelfile)
        logging.info(f"Ollama model {model_name} created successfully.")
    except Exception as e:
        logging.error(f"Error creating Ollama model: {e}")

def create_automatic_report(packets):
    """Generation automatique d'un rapport d'analyse des packrts."""
    
    MODEL_NAME = 'cybersec'
    init_ollama_model(MODEL_NAME)
    
    stream = ollama.chat(
        model=MODEL_NAME,
        messages=[{'role': 'user', 'content': f'Here are the packets to analyze: {packets}'}],
        stream=True,
    )

    for chunk in stream:
        print(chunk['message']['content'], end='', flush=True)



if __name__ == '__main__':

    # Interface réseau à adapter en fonction de votre environnement
    # Exemple : wlp1s0 pour interface Wi-Fi (linux)
    INTERFACE = 'wlp1s0'

    # On va stocker les résultats ici
    packets_additional_info = []

    # Capture des paquets réseau avec pyshark
    capture = pyshark.LiveCapture(interface=INTERFACE)
    logging.info("Starting packet capture...")

    # On traite les paquets capturés
    for packet in capture.sniff_continuously(packet_count=5):  # On limite à 5 packets pour tester
        analysis = process_packet(packet)
        if analysis:
            packets_additional_info.append(analysis)

    # On  affiche les résultats pour comprendre ce que l'on a capturé
    logging.info("\nPaquets capturés et infos sur les paquets:")
    for entry in packets_additional_info:
        print('\n----------------') # Juste pour faire joli
        pprint.pprint(entry) # pretty print pour afficher les infos de manière lisible

    # On génère un rapport d'analyse avec Ollama
    logging.info("\nAnalyse automatique généréé par Ollama :")
    create_automatic_report(packets_additional_info)