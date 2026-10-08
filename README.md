# LOSPICHOS DEFENDER

Scanner de segurança web local para verificar se uma URL parece confiável ou suspeita.

## Funcionalidades

- verificação de HTTPS
- análise de DNS
- resolução de IP
- validação SSL/TLS
- checagem de cabeçalhos HTTP
- análise heurística de risco
- consulta de reputação com VirusTotal
- consulta de reputação com URLhaus
- interface web em HTML + JavaScript



## Estrutura do projeto

```text
site virustotal/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
└── web-scanner/
    └── backend/
```

## Como instalar

1. Clone o projeto
2. Entre na pasta do projeto
3. Crie um ambiente virtual (opcional, mas recomendado)
4. Instale as dependências:

```bash
pip install -r requirements.txt
```

## Como rodar o backend

No Windows PowerShell:

```powershell
cd "c:\Users\SEU_USUARIO\Downloads\PROJETOS\site virustotal"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## Como rodar o frontend

Abra o arquivo abaixo no navegador:

```text
frontend/index.html
```

Ou, se preferir servir a pasta frontend localmente:

```powershell
cd "c:\Users\SEU_USUARIO\Downloads\PROJETOS\site virustotal\frontend"
python -m http.server 5500
```

Depois abra:

```text
http://127.0.0.1:5500/index.html
```

## VirusTotal

Para ativar a verificação real do VirusTotal, configure a variável de ambiente:

```powershell
$env:VT_API_KEY="SUA_CHAVE_AQUI"
```

Depois inicie o backend novamente.

## Observação

Este projeto é um scanner local de uso educacional e não substitui ferramentas profissionais de segurança.

## Licença

Este projeto é disponibilizado apenas para fins educacionais.
