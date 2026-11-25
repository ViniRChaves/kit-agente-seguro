"""Template 1 — Extração estruturada de dados públicos com prova de origem.

Cada registro da saída carrega a URL da fonte em ``fonte_url``. Nada é
criado, removido ou "corrigido": a extração é fiel à fonte, campo a campo.

Fonte de exemplo (API pública, sem chave, sem login):
    https://date.nager.at/api/v3/PublicHolidays/2026/BR

Uso (CLI):
    python3 extracao_dados.py --url https://date.nager.at/api/v3/PublicHolidays/2026/BR --out feriados.csv

Uso (biblioteca):
    >>> from extracao_dados import extrair
    >>> registros = extrair(fetch_json, "https://exemplo.com/api")
    >>> registros[0]["fonte_url"]
    'https://exemplo.com/api'

A saída é validada contra ``schemas/extracao.schema.json`` (validador
stdlib em ``pro/validators``; na Lite, a validação é feita por
``validar_registros`` abaixo, sem dependências externas).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from pathlib import Path

COLUNAS = ["data", "nome_local", "nome_en", "pais", "tipos", "fonte_url"]

# Mapeamento campo a campo, sem alterar valores (ver README da Lite).
MAPEAMENTO = {
    "date": "data",
    "localName": "nome_local",
    "name": "nome_en",
    "countryCode": "pais",
}


def fetch_json(url: str, timeout_s: int = 15) -> object:
    """Busca JSON de uma URL pública. Levanta erro em falha de rede/HTTP."""
    req = urllib.request.Request(url, headers={"User-Agent": "kit-agente-seguro/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extrair(fetcher, url: str) -> list[dict[str, str]]:
    """Extrai registros de ``url`` usando ``fetcher(url) -> objeto JSON``.

    ``fetcher`` é injetável para testes determinísticos (sem rede).
    Espera um array JSON de objetos com os campos do MAPEAMENTO.
    """
    dados = fetcher(url)
    if not isinstance(dados, list):
        raise ValueError("a fonte deve devolver um array JSON de objetos")

    registros: list[dict[str, str]] = []
    for item in dados:
        if not isinstance(item, dict):
            raise ValueError("cada item da fonte deve ser um objeto JSON")
        registro: dict[str, str] = {}
        for origem, destino in MAPEAMENTO.items():
            valor = item.get(origem)
            if valor is None:
                raise ValueError(f"campo ausente na fonte: {origem!r}")
            registro[destino] = str(valor)
        tipos = item.get("types") or []
        if not isinstance(tipos, list):
            raise ValueError("campo 'types' deve ser um array")
        registro["tipos"] = ",".join(str(t) for t in tipos)
        registro["fonte_url"] = url
        registros.append(registro)
    return registros


def validar_registros(registros: list[dict[str, str]], fonte_url: str) -> list[str]:
    """Validação leve (espelho do schema JSON). Devolve lista de erros."""
    erros: list[str] = []
    for i, reg in enumerate(registros):
        for coluna in COLUNAS:
            if coluna not in reg or reg[coluna] == "":
                erros.append(f"linha {i}: coluna ausente/vazia: {coluna}")
        if reg.get("fonte_url") != fonte_url:
            erros.append(f"linha {i}: fonte_url diverge da fonte consultada")
        data = reg.get("data", "")
        if len(data) != 10 or data[4] != "-" or data[7] != "-":
            erros.append(f"linha {i}: data fora do formato ISO aaaa-mm-dd: {data!r}")
    return erros


def escrever_csv(registros: list[dict[str, str]], caminho: str | Path) -> None:
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUNAS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(registros)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="URL pública da fonte JSON")
    parser.add_argument("--out", required=True, help="caminho do CSV de saída")
    args = parser.parse_args(argv)

    registros = extrair(fetch_json, args.url)
    erros = validar_registros(registros, args.url)
    if erros:
        for erro in erros:
            print(f"ERRO: {erro}", file=sys.stderr)
        return 1
    escrever_csv(registros, args.out)
    print(f"{len(registros)} registros extraídos de {args.url} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
