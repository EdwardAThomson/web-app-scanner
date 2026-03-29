"""Module registry for webscan."""

from webscan.modules.testssl import TestSSLModule
from webscan.modules.nuclei import NucleiModule
from webscan.modules.nikto import NiktoModule
from webscan.modules.gitleaks import GitleaksModule
from webscan.modules.semgrep import SemgrepModule
from webscan.modules.trivy import TrivyModule
from webscan.modules.ffuf import FfufModule
from webscan.modules.sqlmap import SqlmapModule
from webscan.modules.headers import HeadersModule
from webscan.modules.api_routes import ApiRoutesModule
from webscan.modules.disclosure import DisclosureModule
from webscan.modules.session import SessionModule
from webscan.modules.forms import FormsModule
from webscan.modules.deps import DepsModule
from webscan.modules.genai import GenaiModule

MODULES: dict[str, type] = {
    "testssl": TestSSLModule,
    "nuclei": NucleiModule,
    "nikto": NiktoModule,
    "semgrep": SemgrepModule,
    "trivy": TrivyModule,
    "gitleaks": GitleaksModule,
    "ffuf": FfufModule,
    "sqlmap": SqlmapModule,
    "headers": HeadersModule,
    "api_routes": ApiRoutesModule,
    "disclosure": DisclosureModule,
    "session": SessionModule,
    "forms": FormsModule,
    "deps": DepsModule,
    "genai": GenaiModule,
}

# Default full-scan order (matches the guide's recommended workflow)
DEFAULT_ORDER = [
    "testssl", "gitleaks", "semgrep", "trivy", "deps",
    "headers", "disclosure", "forms", "session", "api_routes", "genai",
    "nuclei", "nikto", "ffuf", "sqlmap",
]

# Modules safe to run in parallel (no interaction between them)
PARALLEL_GROUPS = [
    ["testssl", "gitleaks", "semgrep", "trivy", "deps", "headers",
     "disclosure", "forms", "session", "api_routes", "genai"],    # Phase 1: independent
    ["nuclei", "nikto"],                                           # Phase 2: remote scanning
    ["ffuf"],                                                      # Phase 3: fuzzing
    ["sqlmap"],                                                    # Phase 4: targeted
]
