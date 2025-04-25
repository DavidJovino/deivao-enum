"""
Módulo de verificação de ferramentas para a pipeline de Bug Bounty.
Responsável por verificar a disponibilidade e versão das ferramentas necessárias.
"""


from pathlib import Path
from core.logger import Logger
from core.executor import CommandExecutor
from config.tools import TOOLS, ESSENTIAL_TOOLS, get_tools_for_module, get_alternatives, requires_special_handling

class ToolChecker:
    """
    Classe para verificação de ferramentas necessárias para a pipeline de Bug Bounty.
    """
    def __init__(self, logger=None):
        """
        Inicializa o verificador de ferramentas.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
        """
        self.logger = logger or Logger("tool_checker")
        self.executor = CommandExecutor(logger)
        self.missing_tools = []
        self.available_tools = []
        self.alternative_tools = {}
    
    def check_tool(self, tool_name):
        """
        Verifica se uma ferramenta está disponível no sistema.
        
        Args:
            tool_name (str): Nome da ferramenta
            
        Returns:
            bool: True se a ferramenta está disponível, False caso contrário
        """
        if tool_name not in TOOLS:
            self.logger.warning(f"Ferramenta desconhecida: {tool_name}")
            return False
        
        tool_info = TOOLS[tool_name]
        
        # Verificar se a ferramenta tem um comando específico
        command = tool_info.get("command", tool_name)
        if not command:
            self.logger.debug(f"Ferramenta {tool_name} não tem comando associado")
            return False
        
        # Verificar se o comando existe
        exists = self.executor.check_command_exists(command)
        
        if exists:
            self.logger.debug(f"Ferramenta {tool_name} encontrada")
            if tool_name not in self.available_tools:
                self.available_tools.append(tool_name)
            return True
        else:
            self.logger.debug(f"Ferramenta {tool_name} não encontrada")
            if tool_name not in self.missing_tools:
                self.missing_tools.append(tool_name)
            return False
    
    def check_tools_for_module(self, module_name):
        """
        Verifica todas as ferramentas necessárias para um módulo específico.
        
        Args:
            module_name (str): Nome do módulo
            
        Returns:
            dict: Dicionário com ferramentas disponíveis, faltantes e alternativas
        """
        self.logger.step(f"Verificando ferramentas para o módulo: {module_name}")
        
        tools = get_tools_for_module(module_name)
        if not tools:
            self.logger.warning(f"Módulo desconhecido ou sem ferramentas: {module_name}")
            return {"available": [], "missing": [], "alternatives": {}}
        
        available = []
        missing = []
        alternatives = {}
        
        for tool in tools:
            if self.check_tool(tool):
                available.append(tool)
            else:
                missing.append(tool)
                # Verificar alternativas
                alt_tools = get_alternatives(tool)
                for alt in alt_tools:
                    if self.check_tool(alt):
                        alternatives[tool] = alt
                        self.logger.info(f"Usando {alt} como alternativa para {tool}")
                        break
        
        # Adicionar alternativas especiais
        for tool, alt in self.alternative_tools.items():
            if tool in missing and tool not in alternatives:
                alternatives[tool] = alt
        
        result = {
            "available": available,
            "missing": missing,
            "alternatives": alternatives
        }
        
        # Registrar resultados
        if missing:
            self.logger.warning(f"Ferramentas faltantes para o módulo {module_name}: {', '.join(missing)}")
            if alternatives:
                self.logger.info(f"Alternativas encontradas: {alternatives}")
        else:
            self.logger.success(f"Todas as ferramentas para o módulo {module_name} estão disponíveis")
        
        return result
    
    def check_essential_tools(self):
        """
        Verifica as ferramentas essenciais para o funcionamento básico da pipeline.
        
        Returns:
            bool: True se todas as ferramentas essenciais estão disponíveis, False caso contrário
        """
        self.logger.step("Verificando ferramentas essenciais")
        
        missing = []
        for tool in ESSENTIAL_TOOLS:
            if not self.executor.check_command_exists(tool):
                missing.append(tool)
        
        if missing:
            self.logger.warning(f"Ferramentas essenciais faltantes: {', '.join(missing)}")
            return False
        else:
            self.logger.success("Todas as ferramentas essenciais estão disponíveis")
            return True
    
    def check_all_tools(self):
        """
        Verifica todas as ferramentas definidas.
        
        Returns:
            dict: Dicionário com ferramentas disponíveis, faltantes e alternativas
        """
        self.logger.step("Verificando todas as ferramentas")
        
        available = []
        missing = []
        alternatives = {}
        
        for tool_name in TOOLS:
            if self.check_tool(tool_name):
                available.append(tool_name)
            else:
                missing.append(tool_name)
        
        # Adicionar alternativas especiais
        for tool, alt in self.alternative_tools.items():
            if tool in missing:
                alternatives[tool] = alt
        
        result = {
            "available": available,
            "missing": missing,
            "alternatives": alternatives
        }
        
        # Registrar resultados
        self.logger.info(f"Ferramentas disponíveis: {len(available)}/{len(TOOLS)}")
        if missing:
            self.logger.warning(f"Ferramentas faltantes: {len(missing)}")
            if alternatives:
                self.logger.info(f"Alternativas encontradas: {len(alternatives)}")
        
        return result
    
    def get_tool_info(self, tool_name):
        """
        Retorna informações detalhadas sobre uma ferramenta.
        
        Args:
            tool_name (str): Nome da ferramenta
            
        Returns:
            dict: Informações da ferramenta ou None se não encontrada
        """
        if tool_name in TOOLS:
            tool_info = TOOLS[tool_name].copy()
            tool_info["available"] = tool_name in self.available_tools
            
            # Adicionar informações de alternativa se aplicável
            if tool_name in self.alternative_tools:
                tool_info["alternative"] = self.alternative_tools[tool_name]
            
            return tool_info
        return None
    
    def print_tool_status(self, tool_name):
        """
        Imprime o status de uma ferramenta específica.
        
        Args:
            tool_name (str): Nome da ferramenta
        """
        if tool_name not in TOOLS:
            self.logger.warning(f"Ferramenta desconhecida: {tool_name}")
            return
        
        tool_info = self.get_tool_info(tool_name)
        available = self.check_tool(tool_name)
        
        if available:
            self.logger.success(f"Ferramenta {tool_name} está disponível")
        else:
            self.logger.warning(f"Ferramenta {tool_name} não está disponível")
            
            # Mostrar alternativas
            alternatives = get_alternatives(tool_name)
            if alternatives:
                alt_available = []
                for alt in alternatives:
                    if self.check_tool(alt):
                        alt_available.append(alt)
                
                if alt_available:
                    self.logger.info(f"Alternativas disponíveis: {', '.join(alt_available)}")
                else:
                    self.logger.warning("Nenhuma alternativa disponível")
            
            # Mostrar alternativa especial
            if tool_name in self.alternative_tools:
                self.logger.info(f"Será usada implementação alternativa: {self.alternative_tools[tool_name]}")
        
        # Mostrar informações adicionais
        if "description" in tool_info:
            self.logger.info(f"Descrição: {tool_info['description']}")
        if "required_for" in tool_info:
            self.logger.info(f"Necessária para módulos: {', '.join(tool_info['required_for'])}")
            
    def get_critical_missing_tools(self):
        """
        Retorna a lista de ferramentas críticas faltantes.
        
        Returns:
            list: Lista de ferramentas críticas faltantes
        """
        critical_tools = []
        for module in ["enum"]:
            tools = get_tools_for_module(module)
            for tool in tools:
                if tool not in self.available_tools and tool not in self.alternative_tools:
                    critical_tools.append(tool)
        
        # Remover duplicatas
        return list(set(critical_tools))