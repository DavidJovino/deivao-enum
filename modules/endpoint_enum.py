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
import shlex
from tqdm import tqdm
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker

class EndpointEnum:
    def __init__(self, logger: Optional[Logger] = None, threads: int = 10, timeout: int = 300, allow_ipv6: bool = False):
        self.logger = logger or Logger("endpoint_enum")
        self.executor = CommandExecutor(self.logger)
        self.threads = threads
        self.timeout = timeout
        self.allow_ipv6 = allow_ipv6
        self.start_time = datetime.now()

        self.tools_status = self._verify_tools()
        self.endpoints: List[str] = []
        self.active_endpoints: List[str] = []
        self.directories: List[str] = []
        self.parameters: List[str] = []

    def _verify_tools(self) -> Dict:
        tools_to_check = {
            'katana': 'katana -version',
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
        """Sanitiza todas as linhas de um arquivo, removendo códigos ANSI e dados extras, mantendo apenas URLs válidas."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        sanitized_lines = []
        for line in lines:
            clean_line = self._sanitize_url(line.strip())
            if clean_line and self._validate_url(clean_line):  # <<< AQUI
                sanitized_lines.append(clean_line)

        with open(file_path, 'w', encoding='utf-8') as f:
            for line in sanitized_lines:
                f.write(line + '\n')

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
        if 'katana' in self.tools_status['available']:
            cmd = f"katana -list {hosts_file} -o {output_file}.katana"
            self.executor.execute(cmd, timeout=self.timeout)
        if 'hakrawler' in self.tools_status['available']:
            cmd = f"cat {hosts_file} | hakrawler -t {self.threads} > {output_file}.hakrawler"
            self.executor.execute(cmd, timeout=self.timeout, shell=True)
        # Combinar resultados
        self.executor.execute(f"cat {output_file}.katana {output_file}.hakrawler | sort -u > {output_file}", shell=True)

    def _run_historical_urls(self, hosts_file: str, output_file: str):
        tool = next((t for t in self.tools_status['historical'] if t in self.tools_status['available']), None)
        if tool == 'gau':
            cmd = f"cat {hosts_file} | cut -d/ -f3 | gau > {output_file}.gau"
        elif tool == 'waybackurls':
            cmd = f"cat {hosts_file} | cut -d/ -f3 | waybackurls > {output_file}.wayback"
        else:
            return
        self.executor.execute(cmd, timeout=self.timeout, shell=True)
        self.executor.execute(f"cat {output_file}* | sort -u >> {output_file}", shell=True)

    def _check_active_endpoints(self, input_file: str, output_file: str, max_threads: int = 30):
        """
        Sanitiza e valida endpoints individualmente usando múltiplas threads para alta performance, com barra de progresso.
        """
        self._sanitize_file(input_file)

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]

        def validate_url(url):
            try:
                command = f"echo {shlex.quote(url)} | httpx -silent -status-code -content-length -title"
                result = self.executor.execute(command, timeout=self.timeout, shell=True)
                if result["success"] and result["stdout"].strip():
                    return (url, True)
                return (url, False)
            except Exception as e:
                self.logger.warning(f"Erro ao validar {url}: {e}")
                return (url, False)

        valid_lines = []
        invalid_lines = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(validate_url, url) for url in lines]
            
            # USAR tqdm para barra de progresso!
            for future in tqdm(as_completed(futures), total=len(futures), desc="Validando endpoints", unit="URL"):
                url, is_valid = future.result()
                if is_valid:
                    valid_lines.append(url)
                else:
                    invalid_lines.append(url)

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

        self.logger.info(f"Check concluído: {len(valid_lines)} válidos, {len(invalid_lines)} inválidos (threads: {max_threads})")

    def _run_directory_fuzzing(self, hosts_file: str, output_file: str):
        fuzzer = next((t for t in self.tools_status['fuzzers'] if t in self.tools_status['available']), None)
        if not fuzzer:
            return
        wordlists_dir = os.environ.get("WORDLISTS_DIR", "/app/wordlists")
        wordlist = os.path.join(wordlists_dir, "Discovery/Web-Content/common.txt")
        with open(hosts_file, 'r') as f:
            hosts = [self._sanitize_host(line.strip()) for line in f if line.strip()]
        random.shuffle(hosts)
        hosts = hosts[:5]
        for host in hosts:
            host = self._sanitize_url(host)
            if fuzzer == 'feroxbuster':
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
