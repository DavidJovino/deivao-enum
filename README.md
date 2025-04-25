# 🕵️‍♂️ Deivao-Enum - Bug Bounty Enumeração

Pipeline automatizada para a fase de **Enumeração de Endpoints** em programas de Bug Bounty.  
Desenvolvido como parte da arquitetura completa da [Deivao Pipeline](https://github.com/DavidJovino/deivao-recon).

---

## 📌 Funcionalidades

- ✅ Processa domínios a partir de resultados da Recon (`final_subdomains.txt`)
- 🧠 Validação e normalização de URLs
- 🌐 Verificação de hosts ativos com `httpx`
- 🔍 Crawling com `katana` e `hakrawler`
- 🗂️ Extração de URLs históricas com `gau` e `waybackurls`
- 📁 Fuzzing de diretórios com `ffuf` ou `feroxbuster`
- 📊 Geração de relatórios em `Markdown`, `HTML` e `JSON`

---

## 🚀 Como Usar

### 🐳 Rodando com Docker

```bash
docker build -t deivao-enum .
docker run --rm -v ~/Documents/Bugbounty:/root/Documents/Bugbounty deivao-enum
```

### 💡 Por padrão, o script lê de:
```
~/Documents/Bugbounty/alvos.txt
```
Com um domínio por linha.

---

## ⚙️ Estrutura Esperada

```
Documents/
└── Bugbounty/
    ├── alvos.txt                    # Domínios a processar
    └── example.com/
        ├── recon/
        │   └── final_subdomains.txt
        └── enum/
            ├── final_enum.txt
            ├── endpoints.txt
            ├── active_endpoints.txt
            └── directories.txt
```

---

## 🧱 Tecnologias Utilizadas

- 🐍 Python 3.11
- 🐳 Docker + Docker Compose
- 🦫 Ferramentas Go: `httpx`, `katana`, `gau`, `waybackurls`, `ffuf`
- 📚 Wordlists do projeto [SecLists](https://github.com/danielmiessler/SecLists)

---

## ✍️ Autor

[David Jovino](https://github.com/DavidJovino)  
🔐 Profissional de cibersegurança com foco em automação para Bug Bounty e Red Team

---

## 🛠️ Roadmap Futuro

- [ ] Detecção de parâmetros vulneráveis
- [ ] Integração com o módulo de vulnerabilidades (`deivao-vuln`)
- [ ] Exportação automática para plataformas de relatórios

---

## 📄 Licença

Este projeto é de uso pessoal e educacional. Consulte o autor antes de uso comercial.
