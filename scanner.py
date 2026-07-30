import socket 
from concurrent.futures import ThreadPoolExecutor
import ipaddress

ip_alvo = input('IP do alvo: ')
ip_teste = ip_alvo
portas = range(1,1025)
open("resultado.txt", "w").close()

def Scan(ip_alvo, porta):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((ip_alvo, porta))
    if result == 0:
        try:
            banner = s.recv(1024).decode().strip()
            print(f"Porta {porta} aberta | {banner}")
            with open("resultado.txt", "a") as f:
    f.write(f"Porta {porta} aberta | {banner}\n")
        except:
            print(f"Porta {porta} aberta")

    s.close()
    
    


def ip_valido (ip_teste):
    try:
        ipaddress.IPv4Address(ip_teste)
        return True
    except ValueError:
        return False


if ip_valido(ip_teste) == False:
    try:
        ip_alvo = socket.gethostbyname(ip_alvo)
        for porta in portas:
                Scan(ip_alvo, porta)
                
    except socket.gaierror:
        print('Host inválido')
        exit()

else: 
    for porta in portas:
        Scan(ip_alvo, porta)
   