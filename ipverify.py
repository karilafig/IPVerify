# -*- coding: utf-8 -*-
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
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return [
            ip,
            data['data']['attributes']['country'],
            data['data']['attributes']['last_analysis_stats']['harmless'],
            data['data']['attributes']['last_analysis_stats']['malicious'],
            data['data']['attributes']['last_analysis_stats']['suspicious'],
            data['data']['attributes']['last_analysis_stats']['undetected'],
            data['data']['attributes']['last_analysis_stats']['timeout'],
            data['data']['attributes']['asn'],
            data['data']['attributes']['as_owner'],
            

        ]

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

    response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)

    decodedResponse = json.loads(response.text)
    data = decodedResponse['data']
    ip = data['ipAddress']
    abuseConfidenceScore = data['abuseConfidenceScore']
    totalReports = data['totalReports']
    country = data['countryCode']

    return [ip, data['abuseConfidenceScore'], data['totalReports'], country]

def verify(api_key_vt, api_key_ipdb):
    global TXT_FILE

    resultados_vt = []
    resultados_ipdb = []

    for linha in TXT_FILE:
        ip = linha.strip()

        resultado_vt = virustotal(ip, api_key_vt)
        if resultado_vt is not None:
            resultados_vt.append(resultado_vt)

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
            writer.writerow(['IP', 'country', 'harmless', 'malicious', 'suspicious', 'undetected', 'timeout', 'ASN', "AS OWNER"])
            for resultado in resultados_vt:
                writer.writerow(resultado)
            print("Arquivo csv 'virustotal_results.csv' gerado.")


        with open('abuseipdb_results.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'Abuse Score', 'Total Reports', 'Country'])
            writer.writerows(resultados_ipdb)
            print("Arquivo csv 'abuseipdb_results.csv' gerado.")
    else:
        print("Arquivo vazio ou não encontrado.")
