import ipaddress
import re
import socket
import subprocess
import time
from tqdm import tqdm
import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import os

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

init()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def salvar(texto):
    with open("resultado.txt", "a", encoding="utf-8") as arquivo:
        arquivo.write(texto + "\n")


def buscar_cves(banner):
    if not banner:
        return

    # tenta pegar OpenSSH especificamente
    match = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner)
    if match:
        termo = f"OpenSSH {match.group(1)}"
    else:
        # regex genérico pra outros serviços
        match = re.search(r"([A-Za-z]{3,})[_\s-](\d+[\.\d]*)", banner)
        if not match:
            return
        termo = f"{match.group(1)} {match.group(2)}"

    for tentativa in range(3):
        try:
            time.sleep(2)
            response = requests.get(
                f"{NVD_API_URL}?keywordSearch={termo}&resultsPerPage=10",
                timeout=15,
                headers={"apiKey": NVD_API_KEY},
            )
            if response.status_code != 200:
                return
            dados = response.json()
            vulnerabilidades = dados.get("vulnerabilities", [])

            recentes = []
            for item in vulnerabilidades:
                cve = item["cve"]
                publicado = cve.get("published", "")
                ano = int(publicado[:4]) if publicado else 0
                if ano >= 2010:
                    recentes.append(item)

            if recentes:
                print(f"{Fore.YELLOW}  CVEs encontrados:{Style.RESET_ALL}")
                salvar("  CVEs encontrados:")
                for item in recentes[:3]:
                    cve = item["cve"]
                    cve_id = cve["id"]
                    descricao = cve["descriptions"][0]["value"][:100]
                    print(f"  {Fore.YELLOW}{cve_id}{Style.RESET_ALL} | {descricao}...")
                    salvar(f"  {cve_id} | {descricao}...")
            else:
                print(f"  Nenhum CVE recente encontrado para: {termo}")
                salvar(f"  Nenhum CVE recente encontrado para: {termo}")
            return
        except Exception:
            if tentativa == 2:
                print(f"  API indisponível após 3 tentativas")
                salvar(f"  API indisponível após 3 tentativas")


def consultar_cves_por_header(header):
    try:
        time.sleep(1)
        response = requests.get(
            f"{NVD_API_URL}?keywordSearch={header}&resultsPerPage=10",
            timeout=15,
            headers={"apiKey": NVD_API_KEY},
        )
        if response.status_code != 200:
            print(f"  API indisponível: {response.status_code}")
            return
        dados = response.json()
        vulnerabilidades = dados.get("vulnerabilities", [])

        recentes = []
        for item in vulnerabilidades:
            cve = item["cve"]
            publicado = cve.get("published", "")
            ano = int(publicado[:4]) if publicado else 0
            if ano >= 2010:
                recentes.append(item)

        if recentes:
            print(f"{Fore.YELLOW}  CVEs encontrados:{Style.RESET_ALL}")
            salvar("  CVEs encontrados:")
            for item in recentes[:3]:
                cve = item["cve"]
                cve_id = cve["id"]
                descricao = cve["descriptions"][0]["value"][:100]
                print(f"  {Fore.YELLOW}{cve_id}{Style.RESET_ALL} | {descricao}...")
                salvar(f"  {cve_id} | {descricao}...")
        else:
            print(f"  Nenhum CVE recente encontrado para: {header}")
            salvar(f"  Nenhum CVE recente encontrado para: {header}")
    except Exception as exc:
        print(f"  Erro CVE: {exc}")


def detectar_tecnologia(ip):
    try:
        resposta = requests.get(f"http://{ip}", timeout=3)
        headers = resposta.headers
        print(f"{Fore.YELLOW}Headers HTTP:{Style.RESET_ALL}")
        salvar("Headers HTTP:")
        for header in ["Server", "X-Powered-By", "X-Generator", "Via"]:
            if header in headers:
                valor = headers[header]
                print(f"  {header}: {valor}")
                salvar(f"  {header}: {valor}")
                consultar_cves_por_header(valor)
    except Exception:
        print("Não foi possível detectar frameworks ou tecnologias web no alvo.")
        salvar("Não foi possível detectar frameworks ou tecnologias web no alvo.")


def detectar_os(ip):
    resultado = subprocess.run(
        ["ping", "-c", "1", ip],
        capture_output=True,
        text=True,
    )
    saida = resultado.stdout.lower()
    if "ttl=64" in saida:
        print(f"{Fore.CYAN}OS provável: Linux{Style.RESET_ALL}")
        salvar("OS provável: Linux")
    elif "ttl=128" in saida:
        print(f"{Fore.CYAN}OS provável: Windows{Style.RESET_ALL}")
        salvar("OS provável: Windows")
    else:
        print(f"{Fore.CYAN}OS desconhecido{Style.RESET_ALL}")
        salvar("OS desconhecido")


def scan_porta(ip_alvo, porta, portas_abertas, banners):
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_obj.settimeout(1.0)
    resultado = socket_obj.connect_ex((ip_alvo, porta))
    if resultado == 0:
        portas_abertas[0] += 1
        try:
            banner = socket_obj.recv(1024).decode().strip()
            banners.append((porta, banner))
            print(f"{Fore.RED}Porta {porta} aberta | {banner}{Style.RESET_ALL}")
            salvar(f"Porta {porta} aberta | {banner}")
        except Exception:
            print(f"{Fore.RED}Porta {porta} aberta{Style.RESET_ALL}")
            salvar(f"Porta {porta} aberta")
    socket_obj.close()


def ip_valido(ip_teste):
    try:
        ipaddress.IPv4Address(ip_teste)
        return True
    except ValueError:
        return False


def main():
    ip_alvo = input("IP do alvo: ")
    ip_teste = ip_alvo
    numero_portas = int(input("Número de portas a serem escaneadas (1-65536): "))

    if numero_portas < 1 or numero_portas > 65536:
        print("Número de portas inválido. O valor deve estar entre 1 e 65536.")
        return

    portas = range(1, numero_portas + 1)
    open("resultado.txt", "w", encoding="utf-8").close()

    inicio = time.time()
    portas_abertas = [0]
    banners = []

    print(f"{Fore.GREEN}")
    print(f"  Alvo: {ip_alvo}")
    print(f"  Portas: 1 - {numero_portas}")
    print(f"  Início: {time.strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"{Style.RESET_ALL}")

    salvar(f"Alvo: {ip_alvo}")
    salvar(f"Portas: 1 - {numero_portas}")
    salvar(f"Início: {time.strftime('%d/%m/%Y %H:%M:%S')}")
    salvar("-" * 40)

    try:
        if not ip_valido(ip_teste):
            ip_alvo = socket.gethostbyname(ip_alvo)

        detectar_os(ip_alvo)
        detectar_tecnologia(ip_alvo)
        salvar("-" * 40)

        with ThreadPoolExecutor(max_workers=100) as executor:
            list(tqdm(
                executor.map(lambda porta: scan_porta(ip_alvo, porta, portas_abertas, banners), portas),
                total=numero_portas,
                desc="Scanning",
                unit="porta"
            ))

        print(f"\n{Fore.CYAN}Consultando CVEs...{Style.RESET_ALL}")
        salvar("\nConsultando CVEs...")
        for porta, banner in banners:
            print(f"\nPorta {porta}:")
            salvar(f"\nPorta {porta}:")
            buscar_cves(banner)
    except socket.gaierror:
        print("Host inválido")
        return

    fim = time.time()
    print(f"\n{Fore.GREEN}Portas abertas: {portas_abertas[0]}{Style.RESET_ALL}")
    print(f"Scan concluído em {fim - inicio:.2f} segundos")
    salvar("-" * 40)
    salvar(f"Portas abertas: {portas_abertas[0]}")
    salvar(f"Scan concluído em {fim - inicio:.2f} segundos")


if __name__ == "__main__":
    main()