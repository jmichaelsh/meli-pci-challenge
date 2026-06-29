"""
step_explainer.py -- helper used by run_demo_steps.py e
run_defended_demo_steps.py para rodar a demo MANUALMENTE, passo a passo.

Cada passo imprime, ANTES de executar qualquer codigo:
  - qual modulo do projeto esta agindo
  - qual e o papel do agente de IA (ou da checagem deterministica) nesse passo
  - o que vai acontecer
  - (quando relevante) qual vulnerabilidade existia na versao anterior e
    como ela foi corrigida na nova arquitetura

E so segue para o proximo passo quando o operador pressiona ENTER --
pensado para ser conduzido manualmente, ao vivo, numa entrevista ou estudo,
nao para rodar sozinho do inicio ao fim.

Defina a variavel de ambiente STEP_AUTOPLAY=1 para pular as pausas (util
para um smoke test rapido sem precisar ficar apertando ENTER).
"""

import json
import os

_WIDTH = 78


class Steps:
    """Contador simples para numerar os passos em sequencia, mesmo quando
    a quantidade de passos varia (ex: um loop de tool-use)."""

    def __init__(self):
        self.n = 0

    def next(self) -> int:
        self.n += 1
        return self.n


def _pause(prompt: str = "\n>>> Pressione ENTER para continuar... "):
    if os.environ.get("STEP_AUTOPLAY") == "1":
        print(prompt.strip() + " [STEP_AUTOPLAY=1 -- continuando automaticamente]")
        return
    input(prompt)


def step(number, title, module, agent_role, what_happens, vulnerability=None, fix=None):
    """Imprime o cabecalho explicativo de um passo e PAUSA antes de executa-lo."""
    print("\n" + "=" * _WIDTH)
    print(f"PASSO {number}: {title}")
    print("=" * _WIDTH)
    print(f"Modulo responsavel : {module}")
    print(f"Papel do agente IA : {agent_role}")
    print(f"O que acontece     : {what_happens}")
    if vulnerability:
        print(f"\n[VULNERABILIDADE NA VERSAO ANTERIOR]\n  {vulnerability}")
    if fix:
        print(f"\n[CORRECAO NESTA ARQUITETURA]\n  {fix}")
    _pause("\n>>> Pressione ENTER para executar este passo... ")


def show_result(label: str, data):
    """Mostra o resultado de um passo ja executado e PAUSA antes do proximo."""
    print(f"\n--- {label} ---")
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print(data)
    _pause("\n>>> Pressione ENTER para ir para o proximo passo... ")
