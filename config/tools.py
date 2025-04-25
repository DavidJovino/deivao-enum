"""
Definições de ferramentas para a pipeline de Bug Bounty.
Contém informações sobre todas as ferramentas utilizadas, incluindo:
- Comando para execução
- Método de instalação
- Dependências
- Módulos que utilizam a ferramenta
- Alternativas disponíveis
"""

# Definição de todas as ferramentas utilizadas na pipeline
TOOLS = { 
    # Ferramentas de enumeração de endpoints
    "httpx": {
        "command": "httpx",
        "package": "github.com/projectdiscovery/httpx/cmd/httpx",
        "install_method": "go",
        "required_for": ["enum", "specific"],
        "alternatives": [],
        "description": "Ferramenta para probing de HTTP"
    },
    "katana": {
        "command": "katana",
        "package": "github.com/projectdiscovery/katana/cmd/katana",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["hakrawler"],
        "description": "Ferramenta de crawling de websites"
    },
    "hakrawler": {
        "command": "hakrawler",
        "package": "github.com/hakluke/hakrawler",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["katana"],
        "description": "Ferramenta de crawling simples e rápida"
    },
    "waybackurls": {
        "command": "waybackurls",
        "package": "github.com/tomnomnom/waybackurls",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["gau"],
        "description": "Ferramenta para extrair URLs do Wayback Machine"
    },
    "gau": {
        "command": "gau",
        "package": "github.com/lc/gau/v2/cmd/gau",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["waybackurls"],
        "description": "Ferramenta para obter URLs conhecidos do AlienVault's OTX, Wayback Machine e Common Crawl"
    },
    "ffuf": {
        "command": "ffuf",
        "package": "github.com/ffuf/ffuf",
        "install_method": "go",
        "required_for": ["enum", "specific"],
        "alternatives": ["feroxbuster"],
        "description": "Ferramenta de fuzzing web rápida"
    },
    "feroxbuster": {
        "command": "feroxbuster",
        "package": "",
        "install_method": "curl",
        "install_command": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash",
        "required_for": ["enum"],
        "alternatives": ["ffuf"],
        "description": "Ferramenta de fuzzing recursiva de diretórios"
    }
}

# Ferramentas essenciais que devem estar presentes para o funcionamento básico
ESSENTIAL_TOOLS = ["curl", "wget", "git", "python3", "pip3"]

# Dependências do sistema que podem ser necessárias
SYSTEM_DEPENDENCIES = {
    "apt": [
        "git", "python3", "python3-pip", "golang", "ruby", "ruby-dev", 
        "nmap", "masscan", "whois", "nikto", "dirb", "sqlmap", "hydra", 
        "wfuzz", "curl", "wget", "zip", "unzip", "jq", "build-essential", 
        "libssl-dev", "libffi-dev", "python3-dev", "chromium-browser"
    ]
}

# Dependências Python que serão instaladas automaticamente
PYTHON_DEPENDENCIES = [
    "requests", "beautifulsoup4", "colorama", "tqdm", "argparse", 
    "pyyaml", "jinja2", "markdown", "python-dateutil"
]

# Mapeamento de módulos para ferramentas necessárias
MODULE_TOOLS = {
    "enum": ["httpx", "katana", "hakrawler", "waybackurls", "gau", "ffuf", "feroxbuster"],
}

# Função para obter ferramentas necessárias para um módulo
def get_tools_for_module(module_name):
    """
    Retorna a lista de ferramentas necessárias para um módulo específico.
    
    Args:
        module_name (str): Nome do módulo
        
    Returns:
        list: Lista de ferramentas necessárias
    """
    if module_name in MODULE_TOOLS:
        return MODULE_TOOLS[module_name]
    elif module_name == "all":
        # Combinar todas as ferramentas de todos os módulos
        all_tools = []
        for tools in MODULE_TOOLS.values():
            all_tools.extend(tools)
        return list(set(all_tools))  # Remover duplicatas
    else:
        return []

# Função para obter alternativas para uma ferramenta
def get_alternatives(tool_name):
    """
    Retorna as alternativas disponíveis para uma ferramenta.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        list: Lista de ferramentas alternativas
    """
    if tool_name in TOOLS and "alternatives" in TOOLS[tool_name]:
        return TOOLS[tool_name]["alternatives"]
    return []

# Função para verificar se uma ferramenta requer tratamento especial
def requires_special_handling(tool_name):
    """
    Verifica se uma ferramenta requer tratamento especial.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        bool: True se a ferramenta requer tratamento especial, False caso contrário
    """
    if tool_name in TOOLS and "special_handling" in TOOLS[tool_name]:
        return TOOLS[tool_name]["special_handling"]
    return False
