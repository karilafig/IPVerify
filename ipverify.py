import time
import requests
import re
import subprocess
import argparse
print("  ___ ______     __        _  __     ")
print(" |_ _|  _ \ \   / /__ _ __(_)/ _|_   _ ")
print("  | || |_) \ \ / / _ \ '__| | |_| | | |")
print("  | ||  __/ \ V /  __/ |  | |  _| |_| | ")
print(" |___|_|     \_/ \___|_|  |_|_|  \__, |")
print("                                  |___/")
#----------------------------VARIÁVEIS GLOBAIS------------------------------
TXT_FILE = []
#----------------------------CLASSE DE VERIFICACAO DE API------------------------------
class APIVerifier:
    def __init__(self):
        self.api_key_vt = ""
        self.last_update_vt = 0
        self.api_key_ipdb = ""
        self.last_update_ipdb = 0

    def check_virustotal_api(self):
        if self.api_key_vt and time.time() - self.last_update_vt < 1800:
            return self.api_key_vt

        self.api_key_vt = input("Digite a chave de API do VirusTotal: ")
        self.last_update_vt = time.time()
        return self.api_key_vt

    def check_abuseipdb_api(self):
        if self.api_key_ipdb and time.time() - self.last_update_ipdb < 1800:
            return self.api_key_ipdb

        self.api_key_ipdb = input("Digite a chave de API do AbuseIPDB: ")
        self.last_update_ipdb = time.time()
        return self.api_key_ipdb

#----------------------------FUNCOES---------------------------------------------
def ler_arquivo(caminho):
    try:
        with open(caminho, "r") as arquivo:
            return arquivo.readlines()
    except FileNotFoundError:
        print("Arquivo não encontrado.")
        return []

def virustotal(ip,api_key):
    # Faz a consulta do IP utilizando a API
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        json_data = response.json()
        print('----- IP:'+ ip + '----- ')
        print('País:'+ response.json()['country'])
        
        detected_urls = response.json()['detected_urls']
        for url in detected_urls:
                print('URL:', url['url'])
                print('Positives:', url['positives'])
                print('Total:', url['total'])
                print('Scan date:', url['scan_date'])

    elif response.status_code == 403:
        print('Acesso negado: verifique a chave de API')
    else:
        print('Erro ao fazer a consulta de IP')
    
    time.sleep(15) # Atraso de 15 segundos entre cada chamada

def verify():
    global TXT_FILE
    api_verifier = APIVerifier()
    api_key_vt = api_verifier.check_virustotal_api()
    api_key_ipdb = api_verifier.check_abuseipdb_api()

    for linha in TXT_FILE:
        ip = linha.strip()
        virustotal(ip,api_key_vt)
        print(f"Verificando IP: {ip}")
        print(f"VirusTotal API Key: {api_key_vt}")
        print(f"AbuseIPDB API Key: {api_key_ipdb}")
        print("Realizando a verificação...\n")


#----------------------------MENU------------------------------------------------

parser = argparse.ArgumentParser(description="Configuração de chaves de API")

# argumentos
parser.add_argument("-vtapi", "--virustotalapi", help="Chave de API do VirusTotal")
parser.add_argument("-ipdbapi", "--abuseipdbapi", help="Chave de API do AbuseIPDB")
parser.add_argument("-f", "--file", help="Arquivo de texto com informações de IPs")

args = parser.parse_args()

api_verifier = APIVerifier()

# Verifica se foi fornecida a chave de API do VirusTotal
if args.virustotalapi:
    api_key_vt = args.virustotalapi
else:
    api_key_vt = api_verifier.check_virustotal_api()

# Verifica se foi fornecida a chave de API do AbuseIPDB
if args.abuseipdbapi:
    api_key_ipdb = args.abuseipdbapi
else:
    api_key_ipdb = api_verifier.check_abuseipdb_api()


# Verifica se foi fornecido um arquivo de texto com informações de IPs
if args.file:
    TXT_FILE = ler_arquivo(args.file)
    if TXT_FILE:
        # Faça o processamento com o array TXT_FILE
        verify()
    else:
        print("Arquivo vazio ou não encontrado.")

