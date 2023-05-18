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
API_KEY_BUFFER_VT = ""
LAST_UPDATE_VT = 0
API_KEY_BUFFER_IPDB = ""
LAST_UPDATE_IPDB = 0
TXT_FILE = []

#----------------------------FUNCOES---------------------------------------------

def ler_arquivo(caminho):
    global TXT_FILE
    try:
        with open(caminho, "r") as arquivo:
            TXT_FILE = arquivo.readlines()
    except FileNotFoundError:
        print("Arquivo não encontrado.")

def verify():
    global TXT_FILE

#----------------------------MENU------------------------------------------------

parser = argparse.ArgumentParser(description="Configuração de chaves de API")

# argumentos
parser.add_argument("-vtapi", "--virustotalapi", help="Chave de API do VirusTotal")
parser.add_argument("-ipdbapi", "--abuseipdbapi", help="Chave de API do AbuseIPDB")
parser.add_argument("-f", "--file", help="Arquivo de texto com informações de IPs")

args = parser.parse_args()

# Verifica se foi fornecida a chave de API do VirusTotal
if args.virustotalapi:
    API_KEY_BUFFER_VT = args.virustotalapi

# Verifica se foi fornecida a chave de API do AbuseIPDB
if args.abuseipdbapi:
    API_KEY_BUFFER_IPDB = args.abuseipdbapi

# Verifica se foi fornecido um arquivo de texto com informações de IPs
if args.file:
    ler_arquivo(args.file)
    if TXT_FILE:
        # Faça o processamento com o array TXT_FILE
        verify()
    else:
        print("Arquivo vazio ou não encontrado.")
