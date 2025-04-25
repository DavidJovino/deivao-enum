#!/usr/bin/env python3
"""
Bug Bounty Enumeração - Aplicação principal (Versão Melhorada)

Este script coordena a execução da enumeração a partir do resultado da recon.
Melhorias incluem:
- Melhor tratamento de erros
- Paralelismo mais eficiente
- Verificação de dependências
- Geração de relatórios aprimorada
- Configuração mais flexível
"""

import os
import sys
import argparse
import traceback
from datetime import datetime
from typing import Dict, Union, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# Adicionar diretório raiz ao path de forma mais segura
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from modules.endpoint_enum import EndpointEnum
from reporting.report_generator import ReportGenerator
from reporting.notify import NotifyManager
from config.settings import (
    DEFAULT_THREADS, 
    DEFAULT_TIMEOUT, 
    DEFAULT_LOG_LEVEL
)

class BugBountyEnum:
    """Classe principal para coordenação da Enumeração de Bug Bounty."""
    
    def __init__(self, args: argparse.Namespace):
        """Inicializa a instância de enumeração.
        
        Args:
            args: Argumentos da linha de comando parseados
        """
        self.args = args
        self.start_time = datetime.now()
        self.domain = self._validate_domain(args.domain)
        
        # Configurações iniciais
        self._setup_logger()
        self._setup_directories()
        self._setup_components()
        
        self.logger.banner("Deivao-Enum - Versão Melhorada")
        self._log_initial_config()
        
        # Notificação inicial se configurado
        if args.notify:
            self._send_start_notification()

    def _validate_domain(self, domain: str) -> str:
        """Valida e padroniza o domínio informado.
        
        Args:
            domain: Domínio a ser validado
            
        Returns:
            Domínio validado e padronizado
            
        Raises:
            ValueError: Se o domínio for inválido
        """
        if not domain:
            raise ValueError("Domínio não especificado")
            
        domain = domain.strip().lower()
        if not all(c.isalnum() or c in ('-', '.') for c in domain):
            raise ValueError(f"Domínio inválido: {domain}")
            
        return domain

    def _setup_logger(self):
        """Configura o sistema de logging com tratamento de erros."""
        try:
            self.logger = Logger(
                name="deivao-enum",
                log_file=self.args.log_file,
                level="DEBUG" if self.args.verbose else DEFAULT_LOG_LEVEL,
            )
        except Exception as e:
            print(f"Falha crítica ao configurar logger: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def _setup_directories(self):
        """Configura os diretórios de saída com estrutura organizada."""
        try:
            # Diretório base organizado por data
            self.output_dir = os.path.expanduser(
                os.path.join("~/Documents/Bugbounty", self.domain)
            )
            
            # Criar estrutura de diretórios
            dir_structure = {
                "enum": ["subdomains", "endpoints", "screenshots"],
                "reports": [],
                "logs": [],
                "temp": []
            }
            
            for main_dir, sub_dirs in dir_structure.items():
                main_path = os.path.join(self.output_dir, main_dir)
                os.makedirs(main_path, exist_ok=True)
                
                for sub_dir in sub_dirs:
                    os.makedirs(os.path.join(main_path, sub_dir), exist_ok=True)
                    
            self.logger.debug(f"Estrutura de diretórios criada em: {self.output_dir}")
            
        except OSError as e:
            self.logger.error(f"Falha ao criar diretórios: {str(e)}")
            raise

    def _setup_components(self):
        """Configura os componentes principais com tratamento de erros."""
        try:
            self.executor = CommandExecutor(
                logger=self.logger,
            )
            
            self.tool_checker = ToolChecker(self.logger)
            
            # Configuração condicional do notificador
            self.notify_manager = NotifyManager(self.logger)
            if self.args.notify_config:
                self._load_notification_config()
                
            self.report_generator = ReportGenerator(
                logger=self.logger
            )
            
        except Exception as e:
            self.logger.error(f"Falha ao configurar componentes: {str(e)}")
            raise

    def _load_notification_config(self):
        """Carrega configuração de notificação com validação."""
        try:
            if not os.path.isfile(self.args.notify_config):
                raise FileNotFoundError(
                    f"Arquivo de configuração não encontrado: {self.args.notify_config}"
                )
                
            self.notify_manager.load_config(self.args.notify_config)
            self.logger.info("Configuração de notificação carregada com sucesso")
            
        except Exception as e:
            self.logger.error(f"Falha ao carregar configuração de notificação: {str(e)}")
            self.args.notify = False  # Desativa notificações se houver falha

    def _log_initial_config(self):
        """Registra a configuração inicial no log de forma organizada."""
        config_details = {
            "Domínio alvo": self.domain,
            "Diretório de saída": self.output_dir,
            "Threads": self.args.threads,
            "Timeout (segundos)": self.args.timeout,
            "Modo verboso": "Ativado" if self.args.verbose else "Desativado",
            "Notificações": "Ativadas" if self.args.notify else "Desativadas",
            "Configuração de notificação": self.args.notify_config or "Padrão"
        }
        
        self.logger.info("Configuração Inicial:")
        for key, value in config_details.items():
            self.logger.info(f"  {key}: {value}")

    def _send_start_notification(self):
        """Envia notificação de início com tratamento de erros."""
        if not self.args.notify:
            return
            
        try:
            message = (
                f"Enumeração iniciada para: {self.domain}\n"
                f"Início: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Threads: {self.args.threads}"
            )
            
            self.notify_manager.notify(
                message=message,
                title=f"Deivao-Enum Iniciada - {self.domain}",
                level="info",
                priority="medium"
            )
        except Exception as e:
            self.logger.error(f"Falha ao enviar notificação inicial: {str(e)}")
            self.args.notify = False  # Desativa notificações em caso de falha

    def run(self) -> Union[Dict, bool]:
        """Executa o fluxo principal de enumeração.
        
        Returns:
            Dict: Resultados consolidados se bem-sucedido
            bool: False se ocorrer falha
        """
        try:
            # Verificação inicial de ferramentas
            if not self._pre_run_checks():
                return False
                
            # Executar enumeração de endpoints
            endpoint_results = self._run_endpoint_enumeration()
            if not endpoint_results:
                return False
                
            # Processar resultados e gerar relatórios
            report_file = self._process_results(endpoint_results)
            
            # Notificação de conclusão
            if self.args.notify:
                self._send_completion_notification(endpoint_results, report_file)
                
            return endpoint_results
            
        except KeyboardInterrupt:
            self.logger.warning("Enumeração interrompida pelo usuário")
            return False
        except Exception as e:
            self.logger.error(f"Erro crítico na enumeração: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return False

    def _pre_run_checks(self) -> bool:
        """Executa verificações pré-execução.
        
        Returns:
            bool: True se todas as verificações passarem
        """
        if self.args.check_only:
            return self.check_tools()
            
        if self.args.install:
            return self.install_tools()
            
        # Verificação básica de ferramentas críticas
        if not self.check_tools(silent=True):
            self.logger.error("Ferramentas críticas faltantes. Use --check-only para detalhes.")
            return False
            
        return True

    def _run_endpoint_enumeration(self) -> Optional[Dict]:
        """Executa a enumeração de endpoints.
        
        Returns:
            Optional[Dict]: Resultados da enumeração ou None em caso de falha
        """
        self.logger.banner("Iniciando Enumeração de Endpoints")

        subdomains_file = self._locate_subdomains_file()
        if not subdomains_file:
            return None

        endpoint_enum = EndpointEnum(
            logger=self.logger,
            threads=self.args.threads,
            timeout=self.args.timeout
        )

        return endpoint_enum.run(
            hosts_file=subdomains_file,
            output_dir=os.path.join(self.output_dir, "enum")
        )

    def _locate_subdomains_file(self) -> Optional[str]:
        """Localiza o arquivo de subdomínios final gerado pela etapa de Recon."""
        expected_path = os.path.expanduser(f"~/Documents/Bugbounty/{self.domain}/recon/final_subdomains.txt")

        if os.path.exists(expected_path):
            self.logger.info(f"Arquivo de subdomínios encontrado: {expected_path}")
            return expected_path

        self.logger.error(f"Arquivo de subdomínios não encontrado em: {expected_path}")
        return None

    def _process_results(self, results: Dict) -> str:
        """Processa resultados e gera relatórios.
        
        Args:
            results: Dicionário com resultados da enumeração
            
        Returns:
            str: Caminho para o relatório principal gerado
        """
        self.logger.banner("Processando Resultados")
        
        # Gerar relatórios em formatos solicitados
        report_file = self._generate_reports(results)
        
        # Exibir resumo
        self._print_summary(results, report_file)
        
        return report_file

    def _generate_reports(self, results: Dict) -> str:
        """Gera relatórios nos formatos configurados.
        
        Args:
            results: Dicionário com resultados da enumeração
            
        Returns:
            str: Caminho para o relatório principal (Markdown)
        """
        reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Dados para o relatório
        report_data = {
            "meta": {
                "title": f"Relatório de Enumeração - {self.domain}",
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": str(datetime.now() - self.start_time),
                "domain": self.domain,
                "command": " ".join(sys.argv)
            },
            "results": results,
            "stats": self._calculate_stats(results)
        }
        
        # Gerar relatório principal (Markdown)
        main_report = os.path.join(reports_dir, f"enum_report_{self.domain}.md")
        self.report_generator.generate_report(report_data, main_report, format="md")
        
        # Gerar formatos adicionais em paralelo
        with ThreadPoolExecutor(max_workers=3) as executor:
            format_tasks = []
            
            if self.args.html_report:
                html_report = main_report.replace(".md", ".html")
                format_tasks.append(executor.submit(
                    self.report_generator.generate_report,
                    report_data, html_report, "html"
                ))
                
            if self.args.json_report:
                json_report = main_report.replace(".md", ".json")
                format_tasks.append(executor.submit(
                    self.report_generator.generate_report,
                    report_data, json_report, "json"
                ))
                
            # Aguardar conclusão das tarefas
            for task in as_completed(format_tasks):
                try:
                    task.result()
                except Exception as e:
                    self.logger.error(f"Erro ao gerar relatório: {str(e)}")
        
        self.logger.success(f"Relatório principal gerado: {main_report}")
        return main_report

    def _calculate_stats(self, results: Dict) -> Dict:
        """Calcula estatísticas dos resultados.
        
        Args:
            results: Dicionário com resultados da enumeração
            
        Returns:
            Dict: Estatísticas calculadas
        """
        stats = {
            "endpoints": {
                "total": len(results.get("endpoints", [])),
                "active": len(results.get("active_endpoints", [])),
                "unique_paths": len(set(
                    ep["path"] for ep in results.get("endpoints", []) 
                    if "path" in ep
                ))
            },
            "subdomains": {
                "total": len(results.get("subdomains", [])),
                "live": len(results.get("live_subdomains", []))
            },
            "processing_time": {
                "start": self.start_time.isoformat(),
                "end": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds()
            }
        }
        
        return stats

    def _print_summary(self, results: Dict, report_file: str):
        """Exibe um resumo dos resultados.
        
        Args:
            results: Dicionário com resultados da enumeração
            report_file: Caminho para o relatório gerado
        """
        self.logger.banner("Resumo da Execução")
        
        stats = self._calculate_stats(results)
        duration = stats["processing_time"]["duration_seconds"]
        
        summary = [
            f"Domínio: {self.domain}",
            f"Duração: {duration:.2f} segundos ({duration/60:.2f} minutos)",
            f"Subdomínios: {stats['subdomains']['total']} (live: {stats['subdomains']['live']})",
            f"Endpoints: {stats['endpoints']['total']} (ativos: {stats['endpoints']['active']})",
            f"Caminhos únicos: {stats['endpoints']['unique_paths']}",
            f"Relatório: {report_file}",
            f"Diretório de resultados: {self.output_dir}"
        ]
        
        for line in summary:
            self.logger.info(line)

    def _send_completion_notification(self, results: Dict, report_file: str):
        """Envia notificação de conclusão.
        
        Args:
            results: Dicionário com resultados da enumeração
            report_file: Caminho para o relatório gerado
        """
        try:
            stats = self._calculate_stats(results)
            duration = stats["processing_time"]["duration_seconds"]
            
            message = (
                f"Enumeração concluída para: {self.domain}\n"
                f"Duração: {duration/60:.2f} minutos\n"
                f"Subdomínios: {stats['subdomains']['total']} (live: {stats['subdomains']['live']})\n"
                f"Endpoints: {stats['endpoints']['total']} (ativos: {stats['endpoints']['active']})\n"
                f"Relatório: {os.path.basename(report_file)}"
            )
            
            attachments = [report_file]
            if self.args.html_report:
                attachments.append(report_file.replace(".md", ".html"))
                
            self.notify_manager.notify(
                message=message,
                title=f"BugBounty Enum Concluída - {self.domain}",
                level="success",
                attachments=attachments,
                priority="high"
            )
        except Exception as e:
            self.logger.error(f"Falha ao enviar notificação de conclusão: {str(e)}")

    def check_tools(self, silent: bool = False) -> bool:
        """Verifica ferramentas necessárias.
        
        Args:
            silent: Se True, suprime saída detalhada
            
        Returns:
            bool: True se todas as ferramentas críticas estão disponíveis
        """
        if not silent:
            self.logger.banner("Verificação de Ferramentas")
            
        tools_status = self.tool_checker.check_all_tools()
        
        # Exibir resumo se não for silencioso
        if not silent:
            self._display_tools_status(tools_status)
            
        # Verificar ferramentas críticas
        critical_missing = self.tool_checker.get_critical_missing_tools()
        if critical_missing:
            if not silent:
                self.logger.error(f"Ferramentas críticas faltantes: {', '.join(critical_missing)}")
            return False
            
        if not silent:
            self.logger.success("Todas as ferramentas críticas estão disponíveis")
        return True

    def _display_tools_status(self, tools_status: Dict):
        """Exibe o status das ferramentas de forma organizada."""
        if not tools_status:
            self.logger.warning("Nenhuma informação de ferramentas disponível")
            return
            
        # Verificar se a estrutura é por módulo
        is_module_based = all(isinstance(v, dict) for v in tools_status.values())
        
        if is_module_based:
            for module, status in tools_status.items():
                self.logger.info(f"\nMódulo: {module}")
                self._log_tool_status(status)
        else:
            self.logger.info("\nResumo Geral:")
            self._log_tool_status(tools_status)

    def _log_tool_status(self, status: Dict):
        """Registra o status de ferramentas individualmente."""
        self.logger.info(f"  Disponíveis: {', '.join(status.get('available', [])) or 'Nenhuma'}")
        self.logger.info(f"  Faltantes: {', '.join(status.get('missing', [])) or 'Nenhuma'}")
        
        if status.get('alternatives'):
            self.logger.info("  Alternativas:")
            for tool, alt in status['alternatives'].items():
                self.logger.info(f"    - {tool}: {alt}")

    def install_tools(self) -> bool:
        """Instala ferramentas necessárias.
        
        Returns:
            bool: True se a instalação foi bem-sucedida
        """
        self.logger.banner("Instalação de Ferramentas")
        
        # Verificar ferramentas faltantes
        missing_tools = self.tool_checker.get_missing_tools()
        if not missing_tools:
            self.logger.success("Todas as ferramentas já estão instaladas")
            return True
            
        self.logger.info(f"Ferramentas a serem instaladas: {', '.join(missing_tools)}")
        

def parse_args() -> argparse.Namespace:
    """Analisa os argumentos da linha de comando.
    
    Returns:
        argparse.Namespace: Argumentos analisados
    """
    parser = argparse.ArgumentParser(
        description="Bug Bounty Enum - Pipeline de Enumeração Automatizada",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Argumento obrigatório
    parser.add_argument(
        "domain",
        help="Domínio alvo para enumeração"
    )
    
    # Argumentos de configuração
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Número de threads para execução paralela"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Timeout para comandos externos em segundos"
    )
    
    # Argumentos de logging e saída
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Ativar modo verboso (DEBUG logging)"
    )
    parser.add_argument(
        "--log-file",
        help="Arquivo para salvar logs detalhados"
    )
    
    # Argumentos de relatório
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Gerar relatório em formato HTML adicional"
    )
    parser.add_argument(
        "--json-report",
        action="store_true",
        help="Gerar relatório em formato JSON adicional"
    )
    
    # Argumentos de notificação
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Ativar notificações de status"
    )
    parser.add_argument(
        "--notify-config",
        help="Arquivo de configuração para notificações"
    )
    
    # Modos especiais
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Apenas verificar ferramentas necessárias"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Instalar ferramentas necessárias automaticamente"
    )
    
    return parser.parse_args()

def main():
    """Função principal de execução do script."""
    try:
        args = parse_args()
        enum = BugBountyEnum(args)
        
        if args.check_only:
            sys.exit(0 if enum.check_tools() else 1)
        elif args.install:
            sys.exit(0 if enum.install_tools() else 1)
            
        success = enum.run()
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"Erro crítico: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()