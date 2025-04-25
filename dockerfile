FROM python:3.11-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/tools:$PATH" \
    TOOLS_DIR="/app/tools" \
    WORDLISTS_DIR="/app/wordlists" \
    DEBIAN_FRONTEND=noninteractive \
    GOPATH=/go \
    GOLANG_VERSION=1.22.3

WORKDIR /app

# Cria estrutura de diretórios primeiro
RUN mkdir -p ${TOOLS_DIR} ${WORDLISTS_DIR} && \
    chmod -R 777 ${TOOLS_DIR} && \
    chmod -R 777 ${WORDLISTS_DIR}

# Copia arquivos necessários
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copia o requirements.txt antes de instalar as dependências
COPY requirements.txt /app/requirements.txt

# Instala dependências do sistema
RUN apt update && apt install -y --no-install-recommends \
    curl git wget unzip jq ruby ruby-dev build-essential \
    python3-pip libpcap-dev libssl-dev zlib1g-dev && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Instala Go
RUN curl -LO https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

# Instala dependências Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python

# Depois copia o resto dos arquivos
COPY . .

# Baixa wordlists com verificação robusta
RUN mkdir -p ${WORDLISTS_DIR} && chmod -R 777 ${WORDLISTS_DIR}
RUN mkdir -p ${WORDLISTS_DIR} && \
    cd ${WORDLISTS_DIR} && \
    wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && unzip SecList.zip && rm -f SecList.zip && \
    cd SecLists-master && \
    mv * .. && \
    cd .. && \
    rm -rf SecLists-master

# Instala ferramentas Go
RUN GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/waybackurls@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/lc/gau/v2/cmd/gau@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/hakluke/hakrawler@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/ffuf/ffuf@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/unfurl@latest

# Configura entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []