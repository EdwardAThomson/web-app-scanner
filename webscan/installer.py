"""Tool installer for webscan.

Automates cloning, building, and linking external tools.
All tools are cloned from source into tools/ and built locally.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console

console = Console()

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
VENV_BIN = Path(sys.executable).parent


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 600, env: dict | None = None) -> bool:
    """Run a command and return True on success."""
    run_env = None
    if env:
        run_env = {**os.environ, **env}
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd, env=run_env,
        )
        if result.returncode != 0:
            console.print(f"[red]Command failed:[/red] {' '.join(cmd)}")
            if result.stderr:
                console.print(f"[dim]{result.stderr[:500]}[/dim]")
            return False
        return True
    except subprocess.TimeoutExpired:
        console.print(f"[red]Timed out:[/red] {' '.join(cmd)}")
        return False
    except FileNotFoundError:
        console.print(f"[red]Command not found:[/red] {cmd[0]}")
        return False


def _go_env() -> dict:
    """Build environment variables for Go builds."""
    home = Path.home()
    goroot = home / "go"
    gopath = home / "gopath"

    # Check common Go locations
    for candidate in [goroot, Path("/usr/local/go"), Path("/usr/lib/go")]:
        if (candidate / "bin" / "go").is_file():
            goroot = candidate
            break

    env = {
        "GOROOT": str(goroot),
        "GOPATH": str(gopath),
        "PATH": f"{goroot / 'bin'}:{gopath / 'bin'}:{os.environ.get('PATH', '')}",
    }
    return env


def _perl_env() -> dict:
    """Build environment variables for Perl."""
    local_lib = Path.home() / "perl5" / "lib" / "perl5"
    if local_lib.is_dir():
        return {"PERL5LIB": str(local_lib)}
    return {}


def _check_prerequisite(name: str, check_cmd: list[str]) -> bool:
    """Check if a prerequisite tool is available."""
    try:
        result = subprocess.run(check_cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ──────────────────────────────────────────────
# Tool definitions
# ──────────────────────────────────────────────

TOOLS = {}


def _register(name: str):
    """Decorator to register an install function."""
    def decorator(func):
        TOOLS[name] = func
        return func
    return decorator


@_register("testssl")
def install_testssl() -> bool:
    """Clone testssl.sh (bash script, no build needed)."""
    tool_dir = TOOLS_DIR / "testssl.sh"
    binary = VENV_BIN / "testssl.sh"

    if binary.is_file():
        console.print("[green]testssl.sh already installed[/green]")
        return True

    console.print("Cloning testssl.sh...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/testssl/testssl.sh.git", str(tool_dir)]):
        return False

    binary.symlink_to(tool_dir / "testssl.sh")
    console.print("[green]testssl.sh installed[/green]")
    return True


@_register("nuclei")
def install_nuclei() -> bool:
    """Clone and build Nuclei from source (Go)."""
    tool_dir = TOOLS_DIR / "nuclei"
    binary = VENV_BIN / "nuclei"

    if binary.is_file():
        console.print("[green]nuclei already installed[/green]")
        return True

    env = _go_env()
    if not _check_prerequisite("go", [env.get("GOROOT", "") + "/bin/go", "version"]):
        # Try plain "go" in PATH
        if not _check_prerequisite("go", ["go", "version"]):
            console.print("[red]Go is required to build nuclei. Install Go first.[/red]")
            console.print("[dim]See: https://go.dev/dl/[/dim]")
            return False

    console.print("Cloning nuclei...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/projectdiscovery/nuclei.git", str(tool_dir)]):
        return False

    console.print("Building nuclei (this may take a few minutes)...")
    if not _run(["go", "build", "-o", str(binary), "."],
                cwd=str(tool_dir / "cmd" / "nuclei"), env=env, timeout=600):
        return False

    console.print("[green]nuclei installed[/green]")
    return True


@_register("gitleaks")
def install_gitleaks() -> bool:
    """Clone and build Gitleaks from source (Go)."""
    tool_dir = TOOLS_DIR / "gitleaks"
    binary = VENV_BIN / "gitleaks"

    if binary.is_file():
        console.print("[green]gitleaks already installed[/green]")
        return True

    env = _go_env()
    if not _check_prerequisite("go", [env.get("GOROOT", "") + "/bin/go", "version"]):
        if not _check_prerequisite("go", ["go", "version"]):
            console.print("[red]Go is required to build gitleaks. Install Go first.[/red]")
            return False

    console.print("Cloning gitleaks...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/gitleaks/gitleaks.git", str(tool_dir)]):
        return False

    console.print("Building gitleaks...")
    if not _run(["go", "build", "-o", str(binary), "."],
                cwd=str(tool_dir), env=env, timeout=300):
        return False

    console.print("[green]gitleaks installed[/green]")
    return True


@_register("trivy")
def install_trivy() -> bool:
    """Clone and build Trivy from source (Go, pinned to v0.58.2)."""
    tool_dir = TOOLS_DIR / "trivy"
    binary = VENV_BIN / "trivy"

    if binary.is_file():
        console.print("[green]trivy already installed[/green]")
        return True

    env = _go_env()
    if not _check_prerequisite("go", [env.get("GOROOT", "") + "/bin/go", "version"]):
        if not _check_prerequisite("go", ["go", "version"]):
            console.print("[red]Go is required to build trivy. Install Go first.[/red]")
            return False

    console.print("Cloning trivy v0.58.2...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1", "--branch", "v0.58.2",
                 "https://github.com/aquasecurity/trivy.git", str(tool_dir)]):
        return False

    console.print("Building trivy (this may take several minutes)...")
    if not _run(["go", "build", "-o", str(binary), "./cmd/trivy"],
                cwd=str(tool_dir), env=env, timeout=900):
        return False

    console.print("[green]trivy installed[/green]")
    return True


@_register("ffuf")
def install_ffuf() -> bool:
    """Clone and build ffuf from source (Go)."""
    tool_dir = TOOLS_DIR / "ffuf"
    binary = VENV_BIN / "ffuf"

    if binary.is_file():
        console.print("[green]ffuf already installed[/green]")
        return True

    env = _go_env()
    if not _check_prerequisite("go", [env.get("GOROOT", "") + "/bin/go", "version"]):
        if not _check_prerequisite("go", ["go", "version"]):
            console.print("[red]Go is required to build ffuf. Install Go first.[/red]")
            return False

    console.print("Cloning ffuf...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/ffuf/ffuf.git", str(tool_dir)]):
        return False

    console.print("Building ffuf...")
    if not _run(["go", "build", "-o", str(binary), "."],
                cwd=str(tool_dir), env=env, timeout=300):
        return False

    console.print("[green]ffuf installed[/green]")
    return True


@_register("nikto")
def install_nikto() -> bool:
    """Clone Nikto and install Perl dependencies."""
    tool_dir = TOOLS_DIR / "nikto"
    binary = VENV_BIN / "nikto.pl"

    if binary.is_file():
        console.print("[green]nikto already installed[/green]")
        return True

    if not _check_prerequisite("perl", ["perl", "-v"]):
        console.print("[red]Perl is required for nikto.[/red]")
        return False

    console.print("Cloning nikto...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/sullo/nikto.git", str(tool_dir)]):
        return False

    binary.symlink_to(tool_dir / "program" / "nikto.pl")

    # Install Perl dependencies
    console.print("Installing Perl modules (JSON, XML::Writer)...")
    _run(["cpan", "-T", "JSON", "XML::Writer"], timeout=120)

    console.print("[green]nikto installed[/green]")
    return True


@_register("sqlmap")
def install_sqlmap() -> bool:
    """Clone SQLMap (Python script, no build needed)."""
    tool_dir = TOOLS_DIR / "sqlmap"
    binary = VENV_BIN / "sqlmap"

    if binary.is_file():
        console.print("[green]sqlmap already installed[/green]")
        return True

    console.print("Cloning sqlmap...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if tool_dir.is_dir():
        shutil.rmtree(tool_dir)

    if not _run(["git", "clone", "--depth", "1",
                 "https://github.com/sqlmapproject/sqlmap.git", str(tool_dir)]):
        return False

    binary.symlink_to(tool_dir / "sqlmap.py")
    console.print("[green]sqlmap installed[/green]")
    return True


@_register("semgrep")
def install_semgrep() -> bool:
    """Install Semgrep via pip."""
    if shutil.which("semgrep"):
        console.print("[green]semgrep already installed[/green]")
        return True

    console.print("Installing semgrep via pip...")
    if not _run([sys.executable, "-m", "pip", "install", "semgrep"], timeout=300):
        return False

    console.print("[green]semgrep installed[/green]")
    return True


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def install_tool(name: str) -> bool:
    """Install a single tool by name. Returns True on success."""
    if name not in TOOLS:
        console.print(f"[red]Unknown tool: {name}[/red]")
        console.print(f"Available: {', '.join(TOOLS.keys())}")
        return False
    return TOOLS[name]()


def install_all() -> dict[str, bool]:
    """Install all tools. Returns {name: success}."""
    results = {}
    for name in TOOLS:
        console.print(f"\n[bold]--- {name} ---[/bold]")
        results[name] = TOOLS[name]()
    return results


def check_prerequisites() -> dict[str, bool]:
    """Check which prerequisites are available."""
    prereqs = {
        "git": _check_prerequisite("git", ["git", "--version"]),
        "go": _check_prerequisite("go", ["go", "version"]) or
              _check_prerequisite("go", [str(Path.home() / "go" / "bin" / "go"), "version"]),
        "perl": _check_prerequisite("perl", ["perl", "-v"]),
        "python": True,  # We're running in Python
    }
    return prereqs
