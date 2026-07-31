# Python Port Scanner & Vulnerability Checker

Um script em Python projetado para realizar varreduras de portas em alvos (IP ou Domínio), identificar serviços a partir de banners, detectar o sistema operacional base (através do TTL de pacotes ICMP), verificar cabeçalhos HTTP e consultar vulnerabilidades conhecidas (CVEs) no NVD (National Vulnerability Database).

## 🚀 Funcionalidades

- **Port Scanner Multithreaded:** Varredura rápida de portas utilizando múltiplas threads e barra de progresso interativa (`tqdm`).
- **Detecção de Sistema Operacional:** Utiliza o ping para analisar o tempo de vida (TTL) dos pacotes e determinar se o alvo provável é Linux ou Windows.
- **Detecção de Tecnologias Web:** Faz requisições HTTP para a porta 80 do alvo e analisa os cabeçalhos (`Server`, `X-Powered-By`, etc.) para identificar frameworks e tecnologias.
- **Consulta de CVEs Automatizada:** Coleta banners das portas abertas e cabeçalhos HTTP para buscar vulnerabilidades (CVEs) recentes (publicadas a partir de 2010) utilizando a API oficial do NIST NVD.
- **Relatório Local:** Todos os resultados obtidos durante o escaneamento são salvos automaticamente no arquivo `resultado.txt`.

## ⚙️ Pré-requisitos

- **Python 3.x** instalado.
- Chave de API do NVD (opcional, porém muito recomendada para evitar bloqueios de taxa). Você pode obter uma gratuitamente no [site do NIST](https://nvd.nist.gov/developers/request-an-api-key).

## 📦 Instalação

1. Clone ou baixe este repositório.
2. Navegue até o diretório do projeto.
3. Instale as dependências necessárias utilizando o arquivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

## 🛠️ Como Usar

1. (Recomendado) Exporte a sua chave de API do NVD como variável de ambiente antes de rodar o script:
   - **Linux / macOS:** `export NVD_API_KEY="sua_chave_aqui"`
   - **Windows:** `set NVD_API_KEY="sua_chave_aqui"`
2. Execute o script:

```bash
python scanner.py
```

3. O script solicitará que você insira as seguintes informações:
   - **IP ou Domínio do alvo** (ex: `192.168.0.1` ou `google.com`)
   - **Número de portas a serem escaneadas** (entre 1 e 65536)
4. Acompanhe os resultados no terminal ou analise o arquivo `resultado.txt` gerado no mesmo diretório.

## ⚠️ Aviso Legal

Este script foi desenvolvido com o propósito exclusivo de fins educacionais e testes de segurança em ambientes autorizados. **O uso desta ferramenta para testar alvos sem consentimento prévio e explícito é ilegal e estritamente proibido.** O desenvolvedor não se responsabiliza pelo mau uso desta ferramenta.
