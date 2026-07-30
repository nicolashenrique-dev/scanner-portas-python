import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import time
from colorama import Fore, Style, init
import subprocess
import requests


init()

ip_alvo = input('IP do alvo: ')
ip_teste = ip_alvo
numero_portas = int(input('Número de portas a serem escaneadas (1-65536): '))
if numero_portas < 1 or numero_portas > 65536:
    print("Número de portas inválido. O valor deve estar entre 1 e 65536.")
    exit()
portas = range(1, numero_portas + 1)
open("resultado.txt", "w").close()
inicio = time.time()


def detectar_tecnologia(ip):
    try:
        r = requests.get(f"http://{ip}", timeout=3)
        headers = r.headers
        
        print(f"{Fore.YELLOW}Headers HTTP:{Style.RESET_ALL}")
        for header in ["Server", "X-Powered-By", "X-Generator", "Via"]:
            if header in headers:
                print(f"  {header}: {headers[header]}")
    except:
        print("Não foi possível detectar frameworks ou tecnologias web no alvo.")

def detectar_os(ip):
    resultado = subprocess.run(
        ["ping", "-c", "1", ip],
        capture_output=True,
        text=True
    )
    if "ttl=64" in resultado.stdout.lower():
        print(f"{Fore.CYAN}OS provável: Linux{Style.RESET_ALL}")
    elif "ttl=128" in resultado.stdout.lower():
        print(f"{Fore.CYAN}OS provável: Windows{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}OS desconhecido{Style.RESET_ALL}")


def Scan(ip_alvo, porta):
    '''socket.socket() — cria um novo socket. Os dois parâmetros definem o tipo:

    socket.AF_INET — família de endereços. AF_INET significa IPv4 — os endereços no formato 192.168.1.1. Se fosse IPv6 seria AF_INET6.

    socket.SOCK_STREAM — tipo de conexão. SOCK_STREAM significa TCP — conexão confiável que garante que os dados chegam na ordem certa. Se fosse UDP seria SOCK_DGRAM.'''

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((ip_alvo, porta))
    if result == 0:
        try:
            banner = s.recv(1024).decode().strip()
            print(f"{Fore.RED}Porta {porta} aberta | {banner}{Style.RESET_ALL}")
            with open("resultado.txt", "a") as f:
                f.write(f"Porta {porta} aberta | {banner}\n")
        except:
            print(f"{Fore.RED}Porta {porta} aberta{Style.RESET_ALL}")
            with open("resultado.txt", "a") as f:
                f.write(f"Porta {porta} aberta\n")

    s.close()


def ip_valido(ip_teste):
    try:
        ipaddress.IPv4Address(ip_teste)
        return True
    except ValueError:
        return False


if ip_valido(ip_teste) == False:
    try:
        ip_alvo = socket.gethostbyname(ip_alvo)
        detectar_os(ip_alvo)
        detectar_tecnologia(ip_alvo)
        for porta in portas:
            Scan(ip_alvo, porta)

    except:
        print('Host inválido')
        exit()

else:
    detectar_os(ip_alvo)
    detectar_tecnologia(ip_alvo)

    for porta in portas:
        Scan(ip_alvo, porta)

fim = time.time()
print(f"\nScan concluído em {fim - inicio:.2f} segundos")
   