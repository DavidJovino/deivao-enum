'''
Script Separado do massdns, ele ainda não é funcional, será usado apenas no futuro quando eu separar melhor os scripts e deixar a pipeline mais organizada
'''

import subprocess
import tempfile
import os

def massdns(input_file: str, output_file: str, resolvers_file: str = "resolvers.txt"):
    """
    Executa o massdns em uma lista de subdomínios e salva apenas os que resolveram.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp_output:
        temp_output_path = tmp_output.name

    command = [
        "massdns",
        "-r", resolvers_file,
        "-t", "A",
        "-o", "S",
        "-w", temp_output_path,
        input_file
    ]

    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    resolved_subs = set()
    with open(temp_output_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if parts:
                resolved_subs.add(parts[0])

    os.remove(temp_output_path)

    with open(output_file, "w", encoding="utf-8") as f:
        for sub in sorted(resolved_subs):
            f.write(sub + "\n")

    print(f"[+] {len(resolved_subs)} subdomínios resolvidos salvos em {output_file}")
