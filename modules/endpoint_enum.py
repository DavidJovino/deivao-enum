"""
Módulo de enumeração de endpoints para a pipeline de Bug Bounty.
Versão corrigida com:
- Validação de URLs
- Melhor tratamento de erros
- Verificação robusta de ferramentas
- Suporte a IPv6 configurável
"""

import os
import re
import random
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker

class EndpointEnum:
    """
    Classe para enumeração de endpoints em hosts alvo.
    Versão corrigida e melhorada.
    """
    
    def __init__(self, logger: Optional[Logger] = None, threads: int = 10, 
                 timeout: int = 300, allow_ipv6: bool = False):
        """
        Inicializa o enumerador de endpoints com configurações robustas.
        
        Args:
            logger: Instância de logger
            threads: Número de threads para execução paralela
            timeout: Timeout para comandos em segundos
            allow_ipv6: Se permite endereços IPv6
        """
        self.logger = logger or Logger("endpoint_enum")
        self.executor = CommandExecutor(self.logger)
        self.threads = threads
        self.timeout = timeout
        self.allow_ipv6 = allow_ipv6
        
        # Verificação robusta de ferramentas
        self.tools_status = self._verify_tools()
        
        # Resultados
        self.endpoints: List[str] = []
        self.active_endpoints: List[str] = []
        self.directories: List[str] = []
        self.parameters: List[str] = []

    def _verify_tools(self) -> Dict:
        """Verificação detalhada das ferramentas disponíveis."""
        tools_to_check = {
            'katana': 'katana -version',
            'hakrawler': 'hakrawler -help',
            'httpx': 'httpx -version',
            'ffuf': 'ffuf -h',
            'feroxbuster': 'feroxbuster -h',
            'gau': 'gau -version',
            'waybackurls': 'waybackurls -h'
        }
        
        available = {}
        for tool, cmd in tools_to_check.items():
            result = self.executor.execute(cmd, timeout=10)
            available[tool] = result['success']
            if not result['success']:
                self.logger.warning(f"Ferramenta {tool} não disponível")
        
        return {
            'available': [k for k, v in available.items() if v],
            'missing': [k for k, v in available.items() if not v]
        }

    def _ensure_url_scheme(self, url: str) -> str:
        """Garante que a URL tenha esquema válido."""
        url = url.strip()
        if not re.match(r'^https?://', url):
            url = f'http://{url}'
        return url

    def _validate_url(self, url: str) -> bool:
        """Validação mais robusta de URLs com segurança adicional."""
        try:
            # Verificação básica de formato
            if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url, re.IGNORECASE):
                return False
            
            parsed = urlparse(url)
            
            # Verificação de componentes obrigatórios
            if not all([parsed.scheme, parsed.netloc]):
                return False
                
            # Segurança: evitar SSRF e outros ataques
            if any(block in parsed.netloc for block in ['localhost', '127.', '::1', '0.0.0.0']):
                self.logger.warning(f"URL bloqueada (local/reservada): {url}")
                return False
                
            # Validação de domínio
            if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', parsed.netloc.split(':')[0], re.IGNORECASE):
                if not self.allow_ipv6 or ':' not in parsed.netloc:
                    return False
                    
            return True
        except Exception as e:
            self.logger.debug(f"Erro ao validar URL {url}: {str(e)}")
            return False

    def _prepare_hosts_file(self, input_file: str) -> Optional[str]:
        """Prepara arquivo de hosts com URLs válidas."""
        valid_hosts = []
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    url = self._ensure_url_scheme(line.strip())
                    if self._validate_url(url):
                        valid_hosts.append(url)
        except UnicodeDecodeError:
            self.logger.error(f"Erro de decodificação no arquivo {input_file}")
            return None
        
        if not valid_hosts:
            self.logger.error("Nenhuma URL válida encontrada")
            return None
        
        temp_file = "/tmp/valid_hosts.txt"
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(valid_hosts))
        
        return temp_file

    def run(self, hosts_file: str, output_dir: str) -> Dict:
        """
        Executa a enumeração de endpoints com tratamento robusto de erros.
        
        Args:
            hosts_file: Caminho do arquivo com hosts
            enum_dir: Diretório de saída
            
        Returns:
            Dicionário com resultados e estatísticas
        """
        # Validação inicial
        if not os.path.exists(hosts_file):
            self.logger.error(f"Arquivo não encontrado: {hosts_file}")
            return {"success": False, "error": "Arquivo não encontrado"}
        
        # Preparar hosts válidos
        valid_hosts = self._prepare_hosts_file(hosts_file)
        if not valid_hosts:
            return {"success": False, "error": "Nenhum host válido"}
        
        # Criar diretório de saída
        domain = Path(hosts_file).stem
        enum_dir = output_dir
        os.makedirs(enum_dir, exist_ok=True)
        
        try:
            # 1. Verificar hosts ativos
            active_hosts = self._check_active_hosts(valid_hosts, enum_dir)
            if not active_hosts:
                self.logger.error("Nenhum host ativo encontrado")
                return {"success": False, "error": "Nenhum host ativo"}
            
            # 2. Crawling
            endpoints_file = os.path.join(enum_dir, "endpoints.txt")
            if not self._run_crawler(active_hosts, endpoints_file):
                self.logger.warning("Crawling não obteve resultados")
            
            # 3. URLs históricas
            self._run_historical_urls(valid_hosts, endpoints_file)
            
            # 4. Fuzzing de diretórios
            dirs_file = os.path.join(enum_dir, "directories.txt")
            self._run_directory_fuzzing(active_hosts, dirs_file)
            
            # 5. Consolidar resultados
            return self._consolidate_results(
                endpoints_file,
                os.path.join(enum_dir, "active_endpoints.txt"),
                dirs_file,
                os.path.join(enum_dir, "parameters.txt"),
                enum_dir
            )      
            
        except Exception as e:
            self.logger.error(f"Erro durante enumeração: {str(e)}")
            return {"success": False, "error": str(e)}
        
        # Salvar arquivo final consolidado
        final_enum_path = os.path.join(output_dir, "final_enum.txt")
        try:
            with open(final_enum_path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.active_endpoints or self.endpoints))
            self.logger.success(f"Arquivo final da enumeração salvo em: {final_enum_path}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar final_enum.txt: {str(e)}")

        # Adicionar ao resultado
        results = self._consolidate_results(
            endpoints_file,
            os.path.join(enum_dir, "active_endpoints.txt"),
            dirs_file,
            os.path.join(enum_dir, "parameters.txt"),
            enum_dir
        )

        results["success"] = True
        results["final_file"] = final_enum_path
        return results

    def _run_crawler(self, hosts_file: str, output_file: str) -> bool:
        """Executa crawling com fallback inteligente entre ferramentas."""
        crawlers = self.available_tools.get('crawlers', [])
        
        for tool in crawlers:
            try:
                if tool == 'katana':
                    cmd = (
                        f"katana -list {hosts_file} -jc -kf -d 3 "
                        f"-t {self.threads} -o {output_file} -timeout {self.timeout//2}"
                    )
                elif tool == 'hakrawler':
                    cmd = f"hakrawler -list {hosts_file} -t {self.threads} > {output_file}"
                
                result = self.executor.execute(cmd, timeout=self.timeout, shell=(tool != 'katana'))
                
                if result['success'] and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    self.logger.success(f"Crawling com {tool} obteve resultados")
                    return True
                    
            except Exception as e:
                self.logger.warning(f"Erro com {tool}: {str(e)}")
                continue
                
        self.logger.error("Todos os crawlers falharam")
        return False
    
    def _run_historical_urls(self, hosts_file, output_file):
        """
        Obtém URLs históricas usando waybackurls ou gau.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_file (str): Arquivo de saída para endpoints
            
        Returns:
            bool: True se a obtenção de URLs históricas foi executada com sucesso, False caso contrário
        """
        self.logger.step("Obtendo URLs históricas")
        
        # Verificar se waybackurls ou gau estão disponíveis
        if "gau" in self.tools_status["available"]:
            historical_tool = "gau"
        elif "waybackurls" in self.tools_status["available"]:
            historical_tool = "waybackurls"
        else:
            self.logger.warning("Nenhuma ferramenta de URLs históricas disponível, pulando etapa")
            return False
        
        # Arquivo temporário para resultados
        historical_output = os.path.join(os.path.dirname(output_file), f"{historical_tool}_output.txt")
        
        # Extrair domínios do arquivo de hosts
        domains_file = os.path.join(os.path.dirname(output_file), "domains.txt")
        command = f"cat {hosts_file} | cut -d/ -f3 | sort -u > {domains_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(domains_file) or os.path.getsize(domains_file) == 0:
            self.logger.error("Falha ao extrair domínios do arquivo de hosts")
            return False
        
        # Executar ferramenta de URLs históricas
        if historical_tool == "gau":
            command = f"cat {domains_file} | gau --threads {self.threads} > {historical_output}"
            result = self.executor.execute(command, timeout=self.timeout, shell=True)

            if not result["success"]:
                self.logger.error(f"Falha ao executar gau: {result['stderr']}")
                return False

        else:  # waybackurls
            self.logger.info("Executando waybackurls por subdomínio (modo individual)")
            with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
                domains = [line.strip() for line in f if line.strip()]

            temp_result_file = historical_output + ".tmp"

            with open(temp_result_file, "w") as out_file:
                for domain in domains:
                    cmd = f"echo {domain} | waybackurls"
                    result = self.executor.execute(cmd, timeout=60, shell=True)

                    if result["success"]:
                        out_file.write(result["stdout"])
                    else:
                        self.logger.warning(f"waybackurls falhou para {domain}: {result['stderr']}")

            # Ordenar e deduplicar
            command = f"cat {temp_result_file} | sort -u > {historical_output}"
            result = self.executor.execute(command, timeout=20, shell=True)

            if not result["success"]:
                self.logger.error(f"Erro ao ordenar resultados do waybackurls: {result['stderr']}")
                return False

            if os.path.exists(temp_result_file):
                os.remove(temp_result_file)

        
        # Verificar se o arquivo foi criado
        if not os.path.exists(historical_output) or os.path.getsize(historical_output) == 0:
            self.logger.warning(f"Nenhuma URL histórica encontrada com {historical_tool}")
            return False
        
        # Adicionar resultados ao arquivo de endpoints
        command = f"cat {historical_output} >> {output_file}"
        result = self.executor.execute(command, timeout=10)
        
        if not result["success"]:
            self.logger.error(f"Falha ao adicionar resultados do {historical_tool} ao arquivo de endpoints: {result['stderr']}")
            return False
        
        # Contar URLs históricas
        with open(historical_output, "r", encoding="utf-8", errors="ignore") as f:
            urls = f.read().splitlines()
        
        self.logger.success(f"Encontradas {len(urls)} URLs históricas com {historical_tool}")
        return True
    
    def _run_directory_fuzzing(self, hosts_file, output_file):
        """
        Executa fuzzing de diretórios usando ffuf ou feroxbuster.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_file (str): Arquivo de saída para diretórios
            
        Returns:
            bool: True se o fuzzing foi executado com sucesso, False caso contrário
        """
        self.logger.step("Executando fuzzing de diretórios")
        
        # Verificar se ffuf ou feroxbuster estão disponíveis
        if "ffuf" in self.tools_status["available"]:
            fuzzer = "ffuf"
        elif "feroxbuster" in self.tools_status["available"]:
            fuzzer = "feroxbuster"
        else:
            self.logger.warning("Nenhum fuzzer disponível, pulando fuzzing de diretórios")
            return False
        
        # Verificar se o arquivo de hosts existe
        if not hosts_file or not os.path.exists(hosts_file) or os.path.getsize(hosts_file) == 0:
            self.logger.warning("Arquivo de hosts vazio ou não encontrado, pulando fuzzing de diretórios")
            return False
        
        # Arquivo temporário para resultados
        fuzzer_output = os.path.join(os.path.dirname(output_file), f"{fuzzer}_output.txt")
        
        # Diretório base das wordlists (setado no Docker)
        wordlists_dir = os.environ.get("WORDLISTS_DIR", "/app/wordlists")

        # Caminhos alternativos
        wordlist_candidates = [
            os.path.join(wordlists_dir, "Discovery/Web-Content/common.txt"),
            os.path.join(wordlists_dir, "Discovery/Web-Content/directory-list-2.3-medium.txt")
        ]

        # Verifica qual wordlist existe
        wordlist = None
        for candidate in wordlist_candidates:
            if os.path.exists(candidate):
                wordlist = candidate
                break

        if not wordlist:
            self.logger.warning("Nenhuma wordlist encontrada, pulando fuzzing de diretórios")
            return False

        
        # Ler hosts do arquivo
        with open(hosts_file, "r", encoding="utf-8", errors="ignore") as f:
            hosts = f.read().splitlines()
        
        # Limitar número de hosts para fuzzing
        max_hosts = 5
        if len(hosts) > max_hosts:
            self.logger.info(f"Limitando fuzzing para {max_hosts} hosts aleatórios")
            hosts = random.sample(hosts, max_hosts)
        
        # Executar fuzzing para cada host
        success = False
        for host in hosts:
            self.logger.info(f"Executando fuzzing em {host}")
            
            # Arquivo temporário para resultados deste host
            host_output = os.path.join(os.path.dirname(output_file), f"{fuzzer}_{urlparse(host).netloc}.txt")
            
            # Executar fuzzer
            if fuzzer == "ffuf":
                command = f"ffuf -u {host}/FUZZ -w {wordlist} -mc 200,201,202,203,204,301,302,307,401,403,405 -o {host_output} -of csv"
            else:  # feroxbuster
                command = f"feroxbuster -u {host} -w {wordlist} -o {host_output} --silent"
            
            result = self.executor.execute(command, timeout=self.timeout)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao executar {fuzzer} em {host}: {result['stderr']}")
                continue
            
            # Verificar se o arquivo foi criado
            if not os.path.exists(host_output) or os.path.getsize(host_output) == 0:
                self.logger.warning(f"Nenhum diretório encontrado em {host}")
                continue
            
            # Processar resultados
            if fuzzer == "ffuf":
                # Extrair URLs do CSV
                command = f"tail -n +2 {host_output} | cut -d ',' -f 2 >> {fuzzer_output}"
            else:  # feroxbuster
                # Extrair URLs
                command = f"cat {host_output} | grep -o 'http[s]*://[^ ]*' >> {fuzzer_output}"
            
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao processar resultados do {fuzzer} para {host}: {result['stderr']}")
                continue
            
            success = True
        
        if not success:
            self.logger.warning("Nenhum diretório encontrado em nenhum host")
            return False
        
        # Adicionar resultados ao arquivo de diretórios
        if os.path.exists(fuzzer_output) and os.path.getsize(fuzzer_output) > 0:
            command = f"cat {fuzzer_output} | sort -u > {output_file}"
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.error(f"Falha ao adicionar resultados do {fuzzer} ao arquivo de diretórios: {result['stderr']}")
                return False
            
            # Contar diretórios
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                directories = f.read().splitlines()
            
            self.logger.success(f"Encontrados {len(directories)} diretórios com {fuzzer}")
            return True
        else:
            self.logger.warning("Nenhum diretório encontrado")
            return False
    
    def _consolidate_results(self, *files) -> Dict:
        """Consolida resultados com verificação de integridade."""
        results = {
            'endpoints': [],
            'active_endpoints': [],
            'directories': [],
            'parameters': [],
            'stats': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat()
            }
        }
        
        # Mapeamento de arquivos para campos
        file_map = {
            'endpoints': (files[0], self._process_endpoints),
            'active': (files[1], self._process_active),
            'directories': (files[2], self._process_dirs),
            'parameters': (files[3], self._process_params)
        }
        
        for field, (file_path, processor) in file_map.items():
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = f.read().splitlines()
                        processed = processor(data)
                        
                        results[field] = processed['data']
                        results['stats'].update(processed['stats'])
            except Exception as e:
                self.logger.error(f"Erro processando {file_path}: {str(e)}")
                
        # Cálculo de estatísticas finais
        results['stats']['duration'] = str(
            datetime.fromisoformat(results['stats']['end_time']) - 
            datetime.fromisoformat(results['stats']['start_time'])
        )
        
        return results

    def _process_hosts_parallel(self, hosts: List[str], process_func: Callable) -> Dict[str, Any]:
        """Processa hosts em paralelo com ThreadPoolExecutor."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(process_func, host): host
                for host in hosts
            }
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    results[host] = future.result()
                except Exception as e:
                    self.logger.error(f"Erro processando {host}: {str(e)}")
                    results[host] = None
                    
        return results

if __name__ == "__main__":
    import json
    import tempfile
    
    # Configuração básica
    logger = Logger("endpoint_enum_test")
    logger.setLevel('DEBUG')  # Para ver todos os detalhes
    
    # 1. Teste com URLs válidas e inválidas
    test_urls = [
        "http://example.com",      # Válido
        "https://test.com/path",   # Válido com caminho
        "example.com",             # Inválido (sem esquema)
        "http://[::1]",            # IPv6 (depende da configuração)
        "httpx://invalid",         # Esquema inválido
        ""                         # Vazio
    ]
    
    # 2. Criar arquivo de teste temporário
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        tmp.write("\n".join([
            "http://test.com",
            "https://example.com/admin",
            "invalid-url.com",
            "http://[::1]"
        ]))
        test_file = tmp.name
    
    # 3. Executar enumeração
    try:
        logger.info("Iniciando testes...")
        
        # Cenário 1: Configuração padrão (sem IPv6)
        enumerator = EndpointEnum(
            logger=logger,
            threads=5,
            timeout=120,
            allow_ipv6=False
        )
        
        logger.info("\n=== TESTE 1: Configuração padrão ===")
        results = enumerator.run(
            hosts_file=test_file,
            enum_dir="test_output"
        )
        
        logger.info(f"\nResultados 1:\n{json.dumps(results, indent=2)}")
        
        # Cenário 2: Com IPv6 habilitado
        logger.info("\n=== TESTE 2: Com IPv6 habilitado ===")
        enumerator_ipv6 = EndpointEnum(
            logger=logger,
            allow_ipv6=True
        )
        
        results_ipv6 = enumerator_ipv6.run(
            hosts_file=test_file,
            enum_dir="test_output_ipv6"
        )
        
        logger.info(f"\nResultados 2 (IPv6):\n{json.dumps(results_ipv6, indent=2)}")
        
        # Cenário 3: Teste de validação manual
        logger.info("\n=== TESTE 3: Validação de URLs ===")
        for url in test_urls:
            valid = enumerator._validate_url(url)
            logger.info(f"URL: {url:<30} | Válida: {valid}")
            
    except Exception as e:
        logger.error(f"Erro durante os testes: {str(e)}")
        
    finally:
        # Limpeza
        if os.path.exists(test_file):
            os.remove(test_file)
        
        logger.info("Testes concluídos. Verifique os diretórios de saída:")
        logger.info(f"- Padrão: test_output/")
        logger.info(f"- IPv6: test_output_ipv6/")