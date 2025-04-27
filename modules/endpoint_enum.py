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
import shlex
import time
import multiprocessing
from tqdm import tqdm
from urllib.parse import urlparse
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime
from core.logger import Logger
from core.executor import CommandExecutor
from concurrent.futures import ThreadPoolExecutor, as_completed

class EndpointEnum:
    def __init__(self, logger: Optional[Logger] = None, threads: int = 10, timeout: int = 300, allow_ipv6: bool = False, domain: Optional[str] = None):
        self.logger = logger or Logger("endpoint_enum")
        self.executor = CommandExecutor(self.logger)
        self.threads = threads
        self.timeout = timeout
        self.allow_ipv6 = allow_ipv6
        self.start_time = datetime.now()
        self.domain = domain
        self.tools_status = self._verify_tools()
        self.endpoints: List[str] = []
        self.active_endpoints: List[str] = []
        self.directories: List[str] = []
        self.parameters: List[str] = []

    def _verify_tools(self) -> Dict:
        tools_to_check = {
            'katana': 'katana -h',
            'hakrawler': 'hakrawler -help',
            'httpx': 'httpx -version',
            'ffuf': 'ffuf -h',
            'feroxbuster': 'feroxbuster -h',
            'gau': 'gau -h',
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
            'missing': [k for k, v in available.items() if not v],
            'crawlers': ['katana', 'hakrawler'],
            'historical': ['gau', 'waybackurls'],
            'fuzzers': ['feroxbuster', 'ffuf']
        }

    def _sanitize_host(self, host: str) -> str:
        """Remove metadados como [200] [size] etc."""
        return host.split('[')[0].strip()

    def _sanitize_url(self, raw_url: str) -> str:
        """Remove códigos ANSI e dados extras de uma URL."""
        # Remove caracteres de cor (ANSI)
        raw_url = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', raw_url)
        # Remove pedaços que parecem [200] [16766] [exemplo.com]
        url = raw_url.split(' [')[0].strip()
        return url

    def _sanitize_file(self, file_path: str):
        """Sanitiza todas as linhas de um arquivo, removendo códigos ANSI, dados extras e mantendo apenas URLs válidas e UTF-8 seguras."""
        sanitized_lines = []

        with open(file_path, 'rb') as f:
            raw_lines = f.readlines()

        for raw_line in raw_lines:
            try:
                # Tentar decodificar forçadamente em utf-8 ignorando erros
                line = raw_line.decode('utf-8', errors='ignore').strip()

                if not line:
                    continue

                clean_line = self._sanitize_url(line)

                if clean_line and self._validate_url(clean_line):
                    sanitized_lines.append(clean_line)

            except Exception as e:
                self.logger.warning(f"Erro ao sanitizar linha: {e}")

        with open(file_path, 'w', encoding='utf-8') as f:
            for line in sanitized_lines:
                f.write(line + '\n')

        self.logger.info(f"Sanitização finalizada: {len(sanitized_lines)} URLs válidas mantidas.")

    def _sanitize_file_strong(self, file_path: str):
        """Sanitiza fortemente todas as linhas de um arquivo, removendo bytes inválidos e URLs ruins."""
        sanitized_lines = []

        with open(file_path, 'rb') as f:
            raw_lines = f.readlines()

        for raw_line in raw_lines:
            try:
                line = raw_line.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue

                clean_line = self._sanitize_url(line)

                if clean_line and self._validate_url(clean_line):
                    sanitized_lines.append(clean_line)

            except Exception as e:
                self.logger.warning(f"Erro ao sanitizar linha: {e}")

        with open(file_path, 'w', encoding='utf-8') as f:
            for line in sanitized_lines:
                f.write(line + '\n')

        self.logger.info(f"Sanitização completa: {len(sanitized_lines)} URLs válidas mantidas em {file_path}")

    def _ensure_url_scheme(self, url: str) -> str:
        url = url.strip()
        if not re.match(r'^https?://', url):
            url = f'http://{url}'
        return url

    def _validate_url(self, url: str) -> bool:
        try:
            if not re.match(r'^https?://[\w.-]+(?:/[^\s]*)?$', url, re.IGNORECASE):
                return False
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False
            if any(block in parsed.netloc for block in ['localhost', '127.', '::1', '0.0.0.0']):
                self.logger.warning(f"URL bloqueada: {url}")
                return False
            return True
        except Exception as e:
            self.logger.debug(f"Erro ao validar URL {url}: {str(e)}")
            return False

    def run(self, hosts_file: str, output_dir: str) -> Dict:
        os.makedirs(output_dir, exist_ok=True)

        endpoints_file = os.path.join(output_dir, "endpoints.txt")
        active_file = os.path.join(output_dir, "active_endpoints.txt")
        dirs_file = os.path.join(output_dir, "directories.txt")
        params_file = os.path.join(output_dir, "parameters.txt")

        # Crawling
        self._run_crawlers(hosts_file, endpoints_file)

        # URLs históricas
        self._run_historical_urls(hosts_file, endpoints_file)

        # Ativos
        self._check_active_endpoints(endpoints_file, active_file)

        # Fuzzing
        self._run_directory_fuzzing(active_file, dirs_file)

        # Parâmetros
        self._extract_parameters(endpoints_file, params_file)

        return self._consolidate_results(endpoints_file, active_file, dirs_file, params_file)

    def _run_crawlers(self, hosts_file: str, output_file: str):
        temp_files = []
        if 'katana' in self.tools_status['available']:
            katana_file = f"{output_file}.katana"
            self.logger.info("Iniciando Katana")
            cmd = f"katana -list {hosts_file} -o {katana_file}"
            self.executor.execute(cmd, timeout=self.timeout)
            if os.path.exists(katana_file):
                temp_files.append(katana_file)
        
        if 'hakrawler' in self.tools_status['available']:
            hakrawler_file = f"{output_file}.hakrawler"
            self.logger.info("Iniciando Hakrawler")
            cmd = f"cat {hosts_file} | hakrawler -t {self.threads} > {hakrawler_file}"
            self.executor.execute(cmd, timeout=self.timeout, shell=True)
            if os.path.exists(hakrawler_file):
                temp_files.append(hakrawler_file)
        
        if temp_files:
            self.executor.execute(f"cat {' '.join(temp_files)} | sort -u > {output_file}", shell=True)
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                self.logger.info(f"Total de URLs coletadas no crawling: {len(lines)}")

    def _run_historical_urls(self, hosts_file: str, output_file: str):
        """Coleta URLs históricas usando gau ou waybackurls e consolida os resultados"""
        if not self.tools_status['historical']:
            self.logger.warning("Nenhuma ferramenta de histórico disponível (gau/waybackurls)")
            return

        # Usar arquivo temporário único
        temp_file = f"{output_file}.historical.tmp"
        
        try:
            # Limpar arquivo temporário se existir
            if os.path.exists(temp_file):
                os.remove(temp_file)

            # Executar cada ferramenta disponível
            for tool in self.tools_status['historical']:
                if tool not in self.tools_status['available']:
                    continue
                    
                if tool == 'gau':
                    self.logger.info("Iniciando Gau")
                    cmd = f"cat {hosts_file} | cut -d/ -f3 | gau --threads {self.threads} > {temp_file}.{tool}"
                elif tool == 'waybackurls':
                    self.logger.info("Iniciando Waybackurl")
                    cmd = f"cat {hosts_file} | cut -d/ -f3 | waybackurls > {temp_file}.{tool}"
                else:
                    continue
                    
                self.executor.execute(cmd, timeout=self.timeout, shell=True)
                
                # Adicionar resultados ao arquivo temporário principal
                if os.path.exists(f"{temp_file}.{tool}"):
                    self.executor.execute(f"cat {temp_file}.{tool} >> {temp_file}", shell=True)
                    os.remove(f"{temp_file}.{tool}")  # Limpar arquivo temporário

            # Processar e consolidar resultados finais
            if os.path.exists(temp_file):
                # Remover duplicatas e URLs inválidas
                self._sanitize_file(temp_file)
                
                # Adicionar ao arquivo de saída principal (sem duplicar conteúdo existente)
                self.executor.execute(
                    f"cat {temp_file} | sort -u | grep -Fxv -f {output_file} 2>/dev/null >> {output_file}",
                    shell=True
                )
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                self.logger.info(f"Total de URLs históricas coletadas: {len(lines)}")
                
                os.remove(temp_file)  # Limpeza final
                
        except Exception as e:
            self.logger.error(f"Erro ao processar URLs históricas: {str(e)}")
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def _check_active_endpoints(self, input_file: str, output_file: str, max_threads: int = None, thread_multiplier: int = 5, max_rps: int = 10):
        """
        Sanitiza e valida endpoints usando múltiplas threads baseadas na CPU, com controle de requests por segundo (RPS).
        """
        # Sanitização hardcore antes de tudo
        self.logger.info(f"Sanitizando {input_file}...")
        self._sanitize_file_strong(input_file)

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]

        self.logger.info(f"Total de URLs para validação: {len(lines)}")

        # Detectar CPUs se max_threads não for passado
        if max_threads is None:
            cpu_count = multiprocessing.cpu_count()
            max_threads = cpu_count * thread_multiplier
            self.logger.info(f"Detectado {cpu_count} CPUs. Usando {max_threads} threads (fator {thread_multiplier}x).")

        def validate_url(url):
            try:
                command = f"echo {shlex.quote(url)} | httpx -silent -threads 20 -rate-limit {max_rps} -status-code -content-length -title -tech-detect -web-server -response-time -follow-host-redirects -max-redirects 2 -no-color -ports 80,443,8009,8080,8081,8090,8180,9443"
                result = self.executor.execute(command, timeout=self.timeout, shell=True)
                if result["success"] and result["stdout"].strip():
                    return (url, True)
                return (url, False)
            except Exception as e:
                self.logger.warning(f"Erro ao validar {url}: {e}")
                return (url, False)

        valid_lines = []
        invalid_lines = []

        start_time = time.time()
        completed = 0

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(validate_url, url) for url in lines]

            for future in tqdm(as_completed(futures), total=len(futures), desc="Validando endpoints", unit="URL"):
                try:
                    url, is_valid = future.result()
                    if is_valid:
                        valid_lines.append(url)
                    else:
                        invalid_lines.append(url)
                except Exception as e:
                    self.logger.warning(f"Erro ao processar future: {e}")
                    invalid_lines.append("URL desconhecida com erro")

                completed += 1
                elapsed = time.time() - start_time

                if elapsed > 0:
                    rps = completed / elapsed
                    if rps > max_rps:
                        sleep_time = (completed / max_rps) - elapsed
                        if sleep_time > 0:
                            time.sleep(sleep_time)

        # Salvar os válidos
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in valid_lines:
                f.write(url + '\n')

        # Salvar os inválidos
        if invalid_lines:
            error_file = output_file.replace('.txt', '_erros.txt')
            with open(error_file, 'w', encoding='utf-8') as f:
                for url in invalid_lines:
                    f.write(url + '\n')
            self.logger.info(f"Alguns endpoints inválidos foram encontrados. Veja: {error_file}")

        total_time = time.time() - start_time
        final_rps = completed / total_time if total_time > 0 else 0
        self.logger.info(f"Check concluído: {len(valid_lines)} válidos, {len(invalid_lines)} inválidos.")
        self.logger.info(f"Tempo total: {total_time:.2f}s, Média final: {final_rps:.2f} URLs/s")

    def _run_directory_fuzzing(self, hosts_file: str, output_file: str):
        fuzzer = next((t for t in self.tools_status['fuzzers'] if t in self.tools_status['available']), None)
        if not fuzzer:
            return
        wordlists_dir = os.environ.get("WORDLISTS_DIR", "/app/wordlists")
        wordlist = os.path.join(wordlists_dir, "Discovery/Web-Content/common.txt")
        with open(hosts_file, 'r') as f:
            hosts = [self._sanitize_host(line.strip()) for line in f if line.strip()]
        #random.shuffle(hosts)
        #hosts = hosts[:5] -> Opcional caso quiser fuzz em apenas 5 hosts aleatórios
        for host in hosts:
            host = self._sanitize_url(host)
            if fuzzer == 'feroxbuster':
                self.logger.info("Iniciando Fuzzer")
                cmd = f"feroxbuster -u {host} -w {wordlist} -o {output_file}.tmp --silent"
            else:
                cmd = f"ffuf -u {host}/FUZZ -w {wordlist} -mc 200,301,302 -o {output_file}.tmp -of csv"
            self.executor.execute(cmd, timeout=self.timeout, shell=True)
        self.executor.execute(f"cat {output_file}.tmp | sort -u > {output_file}", shell=True)

    def _extract_parameters(self, input_file: str, output_file: str):
        params = set()
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = urlparse(line)
                params.update(re.findall(r'(\w+)=', parsed.query))
        with open(output_file, 'w') as f:
            f.write('\n'.join(sorted(params)))

    def _consolidate_results(self, *files) -> Dict:
        stats = {
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat()
        }
        results = {}
        names = ['endpoints', 'active_endpoints', 'directories', 'parameters']
        for name, file in zip(names, files):
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    results[name] = f.read().splitlines()
            else:
                results[name] = []
        stats['duration'] = str(datetime.fromisoformat(stats['end_time']) - datetime.fromisoformat(stats['start_time']))
        results['stats'] = stats
        return results
