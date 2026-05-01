"""
Módulo de verificações de infraestrutura e configuração para deivao-enum.

O que aprendemos no tupai.pt (2026-05-01):
- .git exposto em produção → APP_KEY, credenciais, código-fonte via git objects
- APP_DEBUG=true em produção → stack trace completo em endpoints não autenticados
- composer.json/lock públicos → versões exatas de pacotes, superfície de CVEs
- Endpoint não autenticado triggering 500 → Ignition dump com paths e env vars
- /_ignition/health-check → {"can_execute_commands":true} = debug mode ativo
- Directory listing em /Build/ → assets Unity/WebGL de 145MB expostos
- robots.txt com Sitemap: externo → revela domínio do desenvolvedor
- Cookie com Max-Age=3000000000000 → sessão que nunca expira (ano 97092)
- Header x-scale base64 → identificação de desenvolvedor (apocas@github)
- Instância dev em critecng.com → mesmo app, PHP EOL, sem WAF, sem rate limit
- NTLM probe → vazamento de domínio AD sem autenticação
"""

import os
import re
import time
import base64
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import Logger
from core.executor import CommandExecutor
from config.settings import DEFAULT_THREADS, DEFAULT_TIMEOUT


class InfraChecks:
    """
    Verificações de configuração e exposição de infraestrutura.

    Etapas:
        1. _git_exposure()        — .git exposto (HEAD, config, index, objects)
        2. _debug_mode()          — APP_DEBUG/Ignition/phpinfo/stack traces
        3. _composer_exposure()   — composer.json e composer.lock públicos
        4. _directory_listing()   — listagem de diretórios habilitada
        5. _cookie_analysis()     — flags de segurança e expiração de cookies
        6. _header_secrets()      — headers customizados com dados sensíveis (base64, etc.)
        7. _robots_recon()        — robots.txt → paths ocultos e domínios externos
        8. _rate_limit_check()    — rate limiting em endpoints de autenticação
        9. _dev_instance()        — instâncias de desenvolvimento expostas
        10. _sensitive_paths()    — paths sensíveis (phpinfo, backup, .env variants)
    """

    GIT_PATHS = [
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".git/COMMIT_EDITMSG",
        ".git/refs/heads/master",
        ".git/refs/heads/main",
        ".git/packed-refs",
        ".git/logs/HEAD",
    ]

    DEBUG_PATHS = [
        "phpinfo.php",
        "_debugbar",
        "_debugbar/open",
        "telescope",
        "telescope/api/requests",
        "horizon",
        "_ignition/health-check",
        "debug",
        "info.php",
        "test.php",
        "laravel.log",
        "storage/logs/laravel.log",
    ]

    SENSITIVE_PATHS = [
        ".env",
        ".env.backup",
        ".env.prod",
        ".env.local",
        ".env.example",
        "composer.json",
        "composer.lock",
        "package.json",
        "webpack.mix.js",
        "server.php",
        "artisan",
        ".htaccess",
        "web.config",
        "config.php",
        "configuration.php",
        "wp-config.php",
        "database.yml",
        "secrets.yml",
        "credentials.json",
        "backup.zip",
        "backup.sql",
        "dump.sql",
        "db.sql",
        ".DS_Store",
        "Dockerfile",
        "docker-compose.yml",
        "Makefile",
    ]

    def __init__(self, logger: Optional[Logger] = None,
                 threads: int = DEFAULT_THREADS,
                 timeout: int = DEFAULT_TIMEOUT):
        self.logger = logger or Logger("infra_checks")
        self.executor = CommandExecutor(self.logger)
        self.threads = threads
        self.timeout = timeout

    # ──────────────────────────────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────────────────────────────

    def run(self, targets: List[str], output_dir: str) -> Dict:
        """
        Args:
            targets: Lista de URLs base (ex.: ["https://www.b2b.tupai.pt"])
            output_dir: Diretório de saída
        """
        self.logger.banner("Verificações de Infraestrutura e Configuração")

        infra_dir = os.path.join(output_dir, "infra_checks")
        os.makedirs(infra_dir, exist_ok=True)

        all_findings: List[Dict] = []

        for target in targets:
            self.logger.info(f"Verificando: {target}")
            target_findings = []

            target_findings += self._git_exposure(target, infra_dir)
            target_findings += self._debug_mode(target, infra_dir)
            target_findings += self._composer_exposure(target, infra_dir)
            target_findings += self._directory_listing(target, infra_dir)
            target_findings += self._cookie_analysis(target, infra_dir)
            target_findings += self._header_secrets(target, infra_dir)
            target_findings += self._robots_recon(target, infra_dir)
            target_findings += self._rate_limit_check(target, infra_dir)
            target_findings += self._sensitive_paths(target, infra_dir)

            all_findings += target_findings
            time.sleep(2)

        self._write_report(all_findings, infra_dir)

        return {
            "success": True,
            "findings": all_findings,
            "total": len(all_findings),
        }

    # ──────────────────────────────────────────────────────────────────
    # 1. Git exposure
    # ──────────────────────────────────────────────────────────────────

    def _git_exposure(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Verifica se .git/ está exposto.
        Se HEAD acessível, tenta baixar index e extrair objects (.env, config).
        """
        self.logger.step(f"[git] Verificando .git exposto em {base_url}")
        findings = []
        git_dir = os.path.join(output_dir, "git_dump")
        os.makedirs(git_dir, exist_ok=True)

        # Testa HEAD primeiro
        head_url = f"{base_url}/.git/HEAD"
        r = self._fetch(head_url)
        if not r or "ref:" not in r.get("body", ""):
            return findings

        branch = r["body"].strip()
        self.logger.warning(f"[CRITICAL] .git exposto em {base_url}: {branch}")
        findings.append({
            "severity": "CRITICAL",
            "type": "git_exposed",
            "url": head_url,
            "detail": f"Branch: {branch}",
        })

        # Baixa config para extrair remote URL
        config_r = self._fetch(f"{base_url}/.git/config")
        if config_r and "[remote" in config_r.get("body", ""):
            remote = re.search(r"url\s*=\s*(.+)", config_r["body"])
            if remote:
                findings[0]["git_remote"] = remote.group(1).strip()
                self.logger.warning(f"Git remote: {remote.group(1).strip()}")

        # Baixa index para enumerar arquivos
        index_r = self._fetch_binary(f"{base_url}/.git/index")
        if index_r:
            index_path = os.path.join(git_dir, "index.bin")
            with open(index_path, "wb") as f:
                f.write(index_r)
            tracked_files = self._parse_git_index(index_r)
            findings[0]["tracked_files_count"] = len(tracked_files)
            findings[0]["tracked_files_sample"] = tracked_files[:20]

            # Tenta extrair .env e config/services.php via git objects
            sensitive = [f for f in tracked_files if any(
                k in f[0].lower() for k in [".env", "config/services", "config/database", "seeds/user"]
            )]
            for fname, sha1 in sensitive:
                obj_url = f"{base_url}/.git/objects/{sha1[:2]}/{sha1[2:]}"
                obj_data = self._fetch_binary(obj_url)
                if obj_data:
                    content = self._decompress_git_object(obj_data)
                    if content:
                        obj_file = os.path.join(git_dir, fname.replace("/", "_"))
                        with open(obj_file, "w") as f:
                            f.write(content)
                        self.logger.warning(f"Git object extraído: {fname}")
                        # Caça credenciais no conteúdo
                        creds = self._extract_creds(content)
                        if creds:
                            findings.append({
                                "severity": "CRITICAL",
                                "type": "git_credentials",
                                "url": obj_url,
                                "file": fname,
                                "credentials": creds,
                            })
                time.sleep(1)

        return findings

    def _parse_git_index(self, data: bytes):
        """Parse do git index binário — retorna lista de (filename, sha1)."""
        import struct
        files = []
        try:
            num_entries = struct.unpack(">I", data[8:12])[0]
            offset = 12
            for _ in range(num_entries):
                sha1 = data[offset + 40:offset + 60].hex()
                flags = struct.unpack(">H", data[offset + 60:offset + 62])[0]
                name_len = flags & 0xFFF
                offset += 62
                if name_len < 0xFFF:
                    name = data[offset:offset + name_len].decode("utf-8", errors="replace")
                    offset += name_len + 1
                else:
                    end = data.index(b"\x00", offset)
                    name = data[offset:end].decode("utf-8", errors="replace")
                    offset = end + 1
                entry_size = 62 + len(name) + 1
                offset += (8 - (entry_size % 8)) % 8
                files.append((name, sha1))
        except Exception:
            pass
        return files

    def _decompress_git_object(self, data: bytes) -> Optional[str]:
        """Descomprime um git object (zlib) e retorna o conteúdo."""
        import zlib
        try:
            d = zlib.decompress(data)
            null_idx = d.index(b"\x00")
            return d[null_idx + 1:].decode("utf-8", errors="replace")
        except Exception:
            return None

    def _extract_creds(self, content: str) -> Dict:
        """Extrai credenciais de conteúdo de .env ou config."""
        creds = {}
        patterns = {
            "APP_KEY": r"APP_KEY=(.+)",
            "DB_PASSWORD": r"DB_PASSWORD=(.+)",
            "DB_USERNAME": r"DB_USERNAME=(.+)",
            "DB_DATABASE": r"DB_DATABASE=(.+)",
            "MAIL_PASSWORD": r"MAIL_PASSWORD=(.+)",
            "MAIL_USERNAME": r"MAIL_USERNAME=(.+)",
            "AWS_SECRET": r"AWS_SECRET_ACCESS_KEY=(.+)",
            "STRIPE_SECRET": r"STRIPE_SECRET=(.+)",
            "API_KEY": r"API_KEY=(.+)",
        }
        for name, pattern in patterns.items():
            m = re.search(pattern, content)
            if m and m.group(1).strip() not in ("", "null", '""'):
                creds[name] = m.group(1).strip()
        return creds

    # ──────────────────────────────────────────────────────────────────
    # 2. Debug mode detection
    # ──────────────────────────────────────────────────────────────────

    def _debug_mode(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Detecta APP_DEBUG=true, Ignition, phpinfo, stack traces.
        Aprendido: /afterLoginLoad2 sem auth retorna 953KB de stack trace.
        """
        self.logger.step(f"[debug] Verificando debug mode em {base_url}")
        findings = []

        # Ignition health-check
        r = self._fetch(f"{base_url}/_ignition/health-check")
        if r and "can_execute_commands" in r.get("body", ""):
            findings.append({
                "severity": "HIGH",
                "type": "ignition_exposed",
                "url": f"{base_url}/_ignition/health-check",
                "detail": r["body"][:200],
            })
            self.logger.warning(f"Ignition health-check exposto: {r['body'][:100]}")

        # Endpoints que podem disparar Ignition/stack trace
        trigger_paths = [
            "afterLoginLoad2", "_debugbar/open", "telescope/api/requests",
        ]
        for path in trigger_paths:
            r = self._fetch(f"{base_url}/{path}")
            if r and r.get("status") == 500 and (
                "Ignition" in r.get("body", "") or
                "ErrorException" in r.get("body", "") or
                "app_debug" in r.get("body", "")
            ):
                findings.append({
                    "severity": "CRITICAL",
                    "type": "debug_stack_trace",
                    "url": f"{base_url}/{path}",
                    "detail": "Endpoint não autenticado retorna stack trace completo",
                    "size_bytes": len(r["body"]),
                })
                self.logger.warning(f"Stack trace exposto: {base_url}/{path} ({len(r['body'])}B)")

        # phpinfo
        for path in ["phpinfo.php", "info.php", "test.php"]:
            r = self._fetch(f"{base_url}/{path}")
            if r and "PHP Version" in r.get("body", ""):
                findings.append({
                    "severity": "HIGH",
                    "type": "phpinfo_exposed",
                    "url": f"{base_url}/{path}",
                })
                self.logger.warning(f"phpinfo exposto: {base_url}/{path}")
            time.sleep(1)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 3. Composer exposure
    # ──────────────────────────────────────────────────────────────────

    def _composer_exposure(self, base_url: str, output_dir: str) -> List[Dict]:
        """composer.json e composer.lock expõem versões exatas de pacotes."""
        self.logger.step(f"[composer] Verificando composer.json/lock em {base_url}")
        findings = []

        for fname in ["composer.json", "composer.lock"]:
            r = self._fetch(f"{base_url}/{fname}")
            if r and ('"require"' in r.get("body", "") or '"packages"' in r.get("body", "")):
                out_file = os.path.join(output_dir, f"{base_url.split('//')[1].replace('/', '_')}_{fname}")
                with open(out_file, "w") as f:
                    f.write(r["body"])
                findings.append({
                    "severity": "LOW",
                    "type": "composer_exposed",
                    "url": f"{base_url}/{fname}",
                    "detail": f"Expõe versões exatas de dependências ({len(r['body'])} bytes)",
                })
                self.logger.warning(f"composer exposto: {base_url}/{fname}")
            time.sleep(1)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 4. Directory listing
    # ──────────────────────────────────────────────────────────────────

    def _directory_listing(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Verifica listagem de diretórios em paths comuns.
        Aprendido: simulador.tupai.pt/Build/ listava 145MB de assets Unity.
        """
        self.logger.step(f"[dirlist] Verificando directory listing em {base_url}")
        findings = []

        check_dirs = [
            "Build/", "build/", "dist/", "public/", "storage/",
            "uploads/", "files/", "backup/", "old/", "assets/",
            "static/", "media/", ".well-known/",
        ]

        for d in check_dirs:
            r = self._fetch(f"{base_url}/{d}")
            if r and "Index of /" in r.get("body", ""):
                findings.append({
                    "severity": "MEDIUM",
                    "type": "directory_listing",
                    "url": f"{base_url}/{d}",
                    "detail": "Listagem de diretório habilitada",
                })
                self.logger.warning(f"Directory listing: {base_url}/{d}")
            time.sleep(1)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 5. Cookie analysis
    # ──────────────────────────────────────────────────────────────────

    def _cookie_analysis(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Verifica flags Secure, HttpOnly, SameSite e Max-Age absurdos.
        Aprendido: Max-Age=3000000000000 = sessão que expira no ano 97092.
        """
        self.logger.step(f"[cookies] Analisando cookies de {base_url}")
        findings = []

        r_raw = self.executor.execute(
            f'curl -siL --max-time 10 -A "Mozilla/5.0" "{base_url}" 2>/dev/null',
            timeout=15, shell=True
        )
        if not r_raw["success"]:
            return findings

        headers = r_raw["stdout"]
        for line in headers.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            cookie_str = line[11:].strip()

            issues = []
            if "secure" not in cookie_str.lower() and base_url.startswith("https"):
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_str.lower():
                issues.append("Missing SameSite attribute")
            max_age = re.search(r"max-age=(\d+)", cookie_str, re.IGNORECASE)
            if max_age and int(max_age.group(1)) > 86400 * 365 * 10:
                issues.append(f"Max-Age absurdo: {max_age.group(1)} segundos")

            if issues:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "cookie_misconfiguration",
                    "url": base_url,
                    "detail": f"Cookie: {cookie_str[:100]} | Issues: {', '.join(issues)}",
                })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 6. Header secrets
    # ──────────────────────────────────────────────────────────────────

    def _header_secrets(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Detecta headers suspeitos com dados codificados (base64, hex, JWT).
        Aprendido: x-scale: YXBvY2FzQGdpdGh1Yg== → apocas@github (dev identity).
        """
        self.logger.step(f"[headers] Verificando headers suspeitos em {base_url}")
        findings = []

        r_raw = self.executor.execute(
            f'curl -siL --max-time 10 -A "Mozilla/5.0" "{base_url}" 2>/dev/null | head -50',
            timeout=15, shell=True
        )
        if not r_raw["success"]:
            return findings

        skip_headers = {
            "content-type", "date", "server", "vary", "cache-control",
            "pragma", "expires", "content-length", "transfer-encoding",
            "connection", "strict-transport-security", "x-frame-options",
            "x-content-type-options", "x-xss-protection", "set-cookie",
            "location", "accept-ranges", "last-modified", "etag",
            "access-control-allow-origin", "content-encoding",
        }

        for line in r_raw["stdout"].splitlines():
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            name = name.strip().lower()
            value = value.strip()
            if name in skip_headers or not value:
                continue

            decoded = None
            # Try base64
            try:
                decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
                if not all(32 <= ord(c) <= 126 for c in decoded):
                    decoded = None
            except Exception:
                pass

            if decoded:
                findings.append({
                    "severity": "LOW",
                    "type": "header_data_leak",
                    "url": base_url,
                    "detail": f"Header '{name}: {value}' decodifica para: '{decoded}'",
                })
                self.logger.warning(f"Header leak: {name} → {decoded}")

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 7. robots.txt recon
    # ──────────────────────────────────────────────────────────────────

    def _robots_recon(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Extrai paths Disallow e Sitemap de robots.txt.
        Aprendido: Sitemap: https://critecng.com/cib-loja/sitemap.xml
        revelou o domínio do desenvolvedor e o nome interno da app.
        """
        self.logger.step(f"[robots] Analisando robots.txt de {base_url}")
        findings = []

        r = self._fetch(f"{base_url}/robots.txt")
        if not r or not r.get("body"):
            return findings

        body = r["body"]
        disallowed = re.findall(r"Disallow:\s*(.+)", body)
        sitemaps = re.findall(r"Sitemap:\s*(.+)", body)
        host = base_url.split("//")[-1].split("/")[0]

        for sitemap in sitemaps:
            sitemap = sitemap.strip()
            if host not in sitemap:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "robots_external_sitemap",
                    "url": f"{base_url}/robots.txt",
                    "detail": f"Sitemap externo revela domínio de desenvolvedor/terceiro: {sitemap}",
                    "external_url": sitemap,
                })
                self.logger.warning(f"robots.txt Sitemap externo: {sitemap}")

        admin_paths = [p for p in disallowed if any(
            k in p.lower() for k in ["admin", "backoffice", "manage", "panel", "cms", "dashboard"]
        )]
        if admin_paths:
            findings.append({
                "severity": "LOW",
                "type": "robots_admin_paths",
                "url": f"{base_url}/robots.txt",
                "detail": f"Paths admin expostos no robots.txt: {admin_paths}",
            })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 8. Rate limit check
    # ──────────────────────────────────────────────────────────────────

    def _rate_limit_check(self, base_url: str, output_dir: str) -> List[Dict]:
        """
        Testa ausência de rate limiting em endpoints de autenticação.
        Aprendido: /backoffice/login aceitou 10 tentativas rápidas sem lockout.
        """
        self.logger.step(f"[ratelimit] Testando rate limiting em {base_url}")
        findings = []

        # Detecta login endpoints comuns
        login_paths = [
            "login", "backoffice/login", "admin/login", "wp-login.php",
            "user/login", "auth/login", "signin",
        ]

        for path in login_paths:
            url = f"{base_url}/{path}"
            # Pega token CSRF
            r = self._fetch(url)
            if not r or r.get("status") not in (200, 302):
                continue

            # 5 tentativas rápidas com credenciais falsas
            responses = []
            for i in range(5):
                rr = self.executor.execute(
                    f'curl -si --max-time 8 -X POST "{url}" '
                    f'-d "email=test{i}@fake.com&password=wrongpass{i}" '
                    f'-A "Mozilla/5.0" 2>/dev/null | head -5',
                    timeout=10, shell=True
                )
                if rr["success"]:
                    first_line = rr["stdout"].splitlines()[0] if rr["stdout"].splitlines() else ""
                    code = re.search(r"HTTP/\S+\s+(\d+)", first_line)
                    responses.append(int(code.group(1)) if code else 0)
                time.sleep(0.3)

            # Se nenhuma resposta 429/403/503, sem rate limiting
            if responses and not any(c in (429, 503) for c in responses):
                findings.append({
                    "severity": "HIGH",
                    "type": "no_rate_limit",
                    "url": url,
                    "detail": f"5 tentativas sem lockout. Respostas: {responses}",
                })
                self.logger.warning(f"Sem rate limit em {url}: {responses}")
            break  # Só testa o primeiro encontrado

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 9. Sensitive paths
    # ──────────────────────────────────────────────────────────────────

    def _sensitive_paths(self, base_url: str, output_dir: str) -> List[Dict]:
        """Verifica paths sensíveis conhecidos (.env, backup, config, etc.)."""
        self.logger.step(f"[paths] Verificando paths sensíveis em {base_url}")
        findings = []

        for path in self.SENSITIVE_PATHS:
            r = self._fetch(f"{base_url}/{path}")
            if not r:
                continue

            body = r.get("body", "")
            status = r.get("status", 0)

            # Verifica se é conteúdo real (não 404 customizado)
            is_real = (
                (path == ".env" and "APP_" in body) or
                (path == "composer.json" and '"require"' in body) or
                (path == "composer.lock" and '"packages"' in body) or
                (path == "wp-config.php" and "DB_NAME" in body) or
                (path.endswith(".sql") and ("INSERT INTO" in body or "CREATE TABLE" in body)) or
                (path == ".DS_Store" and status == 200 and len(body) > 0 and "<!DOCTYPE" not in body)
            )

            if is_real:
                findings.append({
                    "severity": "CRITICAL" if path in (".env", "wp-config.php") else "HIGH",
                    "type": "sensitive_file_exposed",
                    "url": f"{base_url}/{path}",
                    "detail": f"Arquivo sensível acessível ({len(body)} bytes)",
                })
                self.logger.warning(f"Arquivo sensível: {base_url}/{path}")
            time.sleep(1)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> Optional[Dict]:
        r = self.executor.execute(
            f'curl -siL --max-time 10 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            f'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" '
            f'"{url}" 2>/dev/null',
            timeout=15, shell=True
        )
        if not r["success"] and not r["stdout"]:
            return None
        lines = r["stdout"].split("\r\n\r\n", 1)
        header_section = lines[0] if lines else ""
        body = lines[1] if len(lines) > 1 else ""
        status_match = re.search(r"HTTP/\S+\s+(\d+)", header_section)
        return {
            "status": int(status_match.group(1)) if status_match else 0,
            "headers": header_section,
            "body": body,
        }

    def _fetch_binary(self, url: str) -> Optional[bytes]:
        r = self.executor.execute(
            f'curl -s --max-time 10 -A "Mozilla/5.0" "{url}" 2>/dev/null',
            timeout=15, shell=True
        )
        if r["success"] and r["stdout"]:
            return r["stdout"].encode("latin-1", errors="replace")
        return None

    # ──────────────────────────────────────────────────────────────────
    # Report
    # ──────────────────────────────────────────────────────────────────

    def _write_report(self, findings: List[Dict], output_dir: str):
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

        out_file = os.path.join(output_dir, "infra_findings.txt")
        with open(out_file, "w") as f:
            f.write(f"=== Infra Checks — {len(findings)} achados ===\n\n")
            for item in findings:
                f.write(f"[{item['severity']}] {item['type']}\n")
                f.write(f"  URL: {item['url']}\n")
                if item.get("detail"):
                    f.write(f"  Detail: {item['detail']}\n")
                f.write("\n")

        summary = {}
        for item in findings:
            sev = item["severity"]
            summary[sev] = summary.get(sev, 0) + 1

        self.logger.info(f"Infra findings: {summary}")
