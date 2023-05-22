#-*- coding: utf-8 -*-
import requests
import re
import subprocess
import argparse
import json
import csv
import time

print('\033[1;95m  ___ ______     __        _  __     \033[0m')
print('\033[1;95m |_ _|  _ \ \   / /__ _ __(_)/ _|_   _ \033[0m')
print('\033[1;95m  | || |_) \ \ / / _ \ \'__| | |_| | | |\033[0m')
print('\033[1;95m  | ||  __/ \ V /  __/ |  | |  _| |_| |\033[0m')
print('\033[1;95m |___|_|     \_/ \___|_|  |_|_|  \__, |\033[0m')
print('\033[1;95m                                  |___/\033[0m')


TXT_FILE = []
requests.packages.urllib3.disable_warnings()

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

def ler_arquivo(caminho):
    try:
        with open(caminho, "r") as arquivo:
            return arquivo.readlines()
    except FileNotFoundError:
        print("Arquivo não encontrado")
        return []

def virustotal(ip, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip}
    response = requests.get(url, params=params, verify=False)

    if response.status_code == 200:
        json_data = response.json()
        detected_urls = response.json()['detected_urls']
        resultados = []

        for url in detected_urls:
            resultado = [ip, url['url'], url['positives'], url['total'], url['scan_date'], response.json()['country']]
            resultados.append(resultado)

        return resultados

    return None


def abuseipdb(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

  
    decodedResponse = json.loads(response.text)
    data = decodedResponse['data']
    ip = data['ipAddress']
    abuseConfidenceScore = data['abuseConfidenceScore']
    totalReports = data['totalReports']
    country = data['countryCode']

    return [ip, data['abuseConfidenceScore'], data['totalReports']]

def verify(api_key_vt, api_key_ipdb):
    global TXT_FILE

    resultados_vt = []
    resultados_ipdb = []

    for linha in TXT_FILE:
        ip = linha.strip()

        resultado_vt = virustotal(ip, api_key_vt)
        if resultado_vt is not None:
            resultados_vt.extend(resultado_vt)

     
        resultado_ipdb = abuseipdb(ip, api_key_ipdb)
        if resultado_ipdb is not None:
            resultados_ipdb.append(resultado_ipdb)

    return resultados_vt, resultados_ipdb



parser = argparse.ArgumentParser(description="Configuração de chaves de API")

parser.add_argument("-vtapi", "--virustotalapi", help="Chave de API do VirusTotal")
parser.add_argument("-ipdbapi", "--abuseipdbapi", help="Chave de API do AbuseIPDB")
parser.add_argument("-f", "--file", help="Arquivo de texto com informações de IPs")

args = parser.parse_args()

api_verifier = APIVerifier()


if args.virustotalapi:
    api_key_vt = args.virustotalapi
else:
    api_key_vt = api_verifier.check_virustotal_api()


if args.abuseipdbapi:
    api_key_ipdb = args.abuseipdbapi
else:
    api_key_ipdb = api_verifier.check_abuseipdb_api()


if args.file:
    TXT_FILE = ler_arquivo(args.file)
    if TXT_FILE:
     
        resultados_vt, resultados_ipdb = verify(api_key_vt, api_key_ipdb)

       
        with open('virustotal_results.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'URL', 'Positives', 'Total', 'Scan Date', 'Country'])
            writer.writerows(resultados_vt)
            print("Arquivo csv 'virustotal_results.csv' gerado.")

 
        with open('abuseipdb_results.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'Abuse Score', 'Total Reports'])
            writer.writerows(resultados_ipdb)
            print("Arquivo csv 'abuseipdb_results.csv' gerado.")

    else:
        print("Arquivo vazio ou não encontrado.")

