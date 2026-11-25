"""Runner de sandbox mínimo — execução isolada de código não confiável.

O que este runner GARANTE
-------------------------
- O processo filho herda um ambiente **limpo**: só variáveis de ambiente
  explicitamente permitidas (por padrão, nenhuma além de ``PATH`` mínimo
  e ``LANG``). Nenhum segredo, token ou credencial do host chega ao filho.
- **Timeout** rígido (padrão 30 s): o filho é morto ao expirar.
- **Diretório de trabalho isolado**: um diretório temporário por execução,
  apagado ao final. O filho não vê o diretório do agente.
- **Limites de recursos** (POSIX): tamanho máximo de arquivo escrito e
  tempo de CPU, via ``resource.setrlimit`` no ``preexec_fn``.
- Saída capturada (stdout/stderr) com teto de tamanho.

O que este runner NÃO garante (limites honestos)
------------------------------------------------
- Não é isolamento de kernel: não bloqueia rede, não impede leitura de
  arquivos do host fora do cwd, não é um container. Para código
  ativamente hostil, use a versão Pro (``pro/sandbox.py``) ou um
  container/VM dedicada.
- O filho roda com o mesmo usuário do processo pai.

Uso
---
>>> from sandbox import run_sandboxed
>>> result = run_sandboxed(["python3", "script.py"], timeout_s=10)
>>> result.returncode, result.stdout
(0, 'ok\\n')
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Teto de saída capturada por stream (1 MiB cada).
MAX_OUTPUT_BYTES = 1_048_576

# Limites de recursos do filho (POSIX).
MAX_CPU_SECONDS = 60
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MiB por arquivo escrito


@dataclass
class SandboxResult:
    """Resultado de uma execução isolada."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    workdir: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Ambiente mínimo: nada do host vaza para o filho."""
    env: dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if extra:
        env.update(extra)
    return env


def _limits() -> None:  # pragma: no cover - executado no filho (POSIX)
    """Limites aplicados ao processo filho antes de executar o comando."""
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    except (ValueError, OSError):
        pass


def run_sandboxed(
    argv: list[str],
    *,
    timeout_s: int = 30,
    input_text: str | None = None,
    extra_env: dict[str, str] | None = None,
    files: dict[str, str] | None = None,
) -> SandboxResult:
    """Executa ``argv`` num subprocesso isolado.

    Args:
        argv: comando e argumentos (ex.: ``["python3", "script.py"]``).
        timeout_s: tempo máximo de execução; ao expirar, o filho é morto.
        input_text: texto enviado ao stdin do filho (ou None).
        extra_env: variáveis de ambiente adicionais (valores explícitos
            do operador — nunca passe segredos aqui sem necessidade).
        files: arquivos a criar no diretório isolado antes de rodar,
            mapeando nome relativo -> conteúdo.

    Returns:
        SandboxResult com returncode, stdout, stderr e flag de timeout.
    """
    with tempfile.TemporaryDirectory(prefix="sandbox-") as tmp:
        workdir = Path(tmp)
        for name, content in (files or {}).items():
            target = workdir / name
            if not str(target.resolve()).startswith(str(workdir.resolve())):
                raise ValueError(f"nome de arquivo fora do sandbox: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        try:
            proc = subprocess.run(
                argv,
                cwd=str(workdir),
                env=_clean_env(extra_env),
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                preexec_fn=_limits if os.name == "posix" else None,
            )
            return SandboxResult(
                returncode=proc.returncode,
                stdout=proc.stdout[-MAX_OUTPUT_BYTES:],
                stderr=proc.stderr[-MAX_OUTPUT_BYTES:],
                timed_out=False,
                workdir=str(workdir),
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                returncode=-1,
                stdout=(exc.stdout or b"").decode("utf-8", "replace")[-MAX_OUTPUT_BYTES:]
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")[-MAX_OUTPUT_BYTES:],
                stderr=(exc.stderr or b"").decode("utf-8", "replace")[-MAX_OUTPUT_BYTES:]
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")[-MAX_OUTPUT_BYTES:],
                timed_out=True,
                workdir=str(workdir),
            )


def run_python_sandboxed(
    code: str,
    *,
    timeout_s: int = 30,
    extra_env: dict[str, str] | None = None,
) -> SandboxResult:
    """Executa um trecho de código Python no sandbox (arquivo temporário)."""
    return run_sandboxed(
        [sys.executable, "script.py"],
        timeout_s=timeout_s,
        extra_env=extra_env,
        files={"script.py": code},
    )
