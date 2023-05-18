
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

#----------------------------VARIAVEIS GLOBAIS----------------------------------
API_KEY_BUFFER_VT= ""
LAST_UPDATE_VT = 0
API_KEY_BUFFER_IPDB= ""
LAST_UPDATE_IPDB = 0
#----------------------------FUNCOES---------------------------------------------


#----------------------------MENU------------------------------------------------

parser = argparse.ArgumentParser(description="Configuração de chaves de API")

# argumentos
parser.add_argument("-vtapi", "--virustotalapi", help="Chave de API do VirusTotal")
parser.add_argument("-ipdbapi", "--abuseipdbapi", help="Chave de API do AbuseIPDB")
parser.add_argument("-f", "--file", help="Arquivo de texto com informações de IPs")


args = parser.parse_args()

# Verifica se foi fornecida a chave de API do VirusTotal
if args.virustotalapi:
    configurar_chave_virustotal(args.virustotalapi)

# Verifica se foi fornecida a chave de API do AbuseIPDB
if args.abuseipdbapi:
    configurar_chave_abuseipdb(args.abuseipdbapi)

# Verifica se foi fornecido um arquivo de texto com informações de IPs
if args.file:
    processar_arquivo_ips(args.file)
