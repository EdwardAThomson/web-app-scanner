"""GenAI and chatbot detection module (pure Python).

Fetches web pages and linked JavaScript bundles to detect the presence of
chatbots, AI assistants, and generative-AI features, then checks for
security concerns:

- Chatbot widget SDKs (Intercom, Drift, Tidio, Crisp, LiveChat, etc.)
- LLM / AI client libraries (OpenAI, Anthropic, LangChain, Cohere, etc.)
- AI-provider API keys exposed in client-side code
- System prompt / instruction leakage in JS bundles
- Model name disclosure (gpt-4, claude, gemini, etc.)
- Chat/completion backend endpoints exposed in JS
- Unauthenticated access to AI features
- Missing payment gate on cost-incurring AI features
- WebSocket or streaming endpoints sent over plain HTTP
"""

import os
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import logged_request

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# (label, pattern matched against script src / iframe src / HTML body)
WIDGET_SDK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Intercom", re.compile(r"intercom(?:\.io|cdn\.com|/widget)", re.I)),
    ("Drift", re.compile(r"drift(?:\.com|cdn\.com|/widget|\.load)", re.I)),
    ("Tidio", re.compile(r"tidio(?:\.co|cdn\.com|/widget)", re.I)),
    ("Crisp", re.compile(r"crisp(?:\.chat|cdn\.com|/client\.js)", re.I)),
    ("LiveChat", re.compile(r"livechat(?:inc\.com|\.com/widget)", re.I)),
    ("Zendesk Chat", re.compile(r"zopim|zendesk.*(?:chat|messaging|web[_-]?widget)", re.I)),
    ("HubSpot Chat", re.compile(r"hubspot.*(?:messages|conversations|chatflow)", re.I)),
    ("Freshdesk/Freshchat", re.compile(r"fresh(?:desk|chat|widget)\.com", re.I)),
    ("Olark", re.compile(r"olark(?:\.com|\.js|\.identify)", re.I)),
    ("Tawk.to", re.compile(r"tawk\.to|embed\.tawk", re.I)),
    ("Chatwoot", re.compile(r"chatwoot(?:\.com|/packs|SDK)", re.I)),
    ("Botpress", re.compile(r"botpress(?:\.com|/webchat|cloud\.botpress)", re.I)),
    ("Voiceflow", re.compile(r"voiceflow(?:\.com|/widget)", re.I)),
    ("Kommunicate", re.compile(r"kommunicate(?:\.io|\.app)", re.I)),
    ("Ada", re.compile(r"ada(?:\.cx|support\.io|/embed)", re.I)),
]

# Patterns matched against JS bundle content to detect AI / LLM usage
GENAI_JS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI client", re.compile(r"(?:openai|OpenAI(?:Api|Client|Configuration))", re.I)),
    ("Anthropic client", re.compile(r"(?:anthropic|AnthropicClient|claude-ai)", re.I)),
    ("LangChain", re.compile(r"langchain|LangChain", re.I)),
    ("LlamaIndex", re.compile(r"llama[_-]?index|LlamaIndex", re.I)),
    ("Cohere", re.compile(r"cohere(?:\.ai|Client|\.com/v\d)", re.I)),
    ("Hugging Face", re.compile(r"huggingface\.co|HfInference", re.I)),
    ("Vercel AI SDK", re.compile(r"ai/(?:react|svelte|vue)|useChat|useCompletion", re.I)),
    ("Amazon Bedrock", re.compile(r"bedrock(?:-runtime|Client)", re.I)),
    ("Azure OpenAI", re.compile(r"azure.*openai|openai\.azure\.com", re.I)),
    ("Google Vertex / Gemini", re.compile(r"vertex(?:ai|\.google)|generativelanguage\.googleapis|@google/generative-ai", re.I)),
    ("Replicate", re.compile(r"replicate\.com/v\d|replicate\.run", re.I)),
    ("Together AI", re.compile(r"together(?:\.xyz|\.ai|computer)", re.I)),
    ("Mistral", re.compile(r"mistral(?:\.ai|Client)", re.I)),
    ("Groq", re.compile(r"groq(?:\.com|Client|cloud)", re.I)),
    ("xAI Grok", re.compile(r"xai(?:\.com|\.sf|Client|api\.x\.ai)", re.I)),
    ("Perplexity", re.compile(r"perplexity\.ai|pplx-api", re.I)),
    ("Dialogflow", re.compile(r"dialogflow(?:\.cloud\.google|\.googleapis|[/.]messenger|Messenger)", re.I)),
    ("Amazon Lex", re.compile(r"lex(?:runtime|\.aws|Client)", re.I)),
    ("Rasa", re.compile(r"rasa(?:\.io|/webchat|WebChat)", re.I)),
    ("Microsoft Bot Framework", re.compile(r"botframework|directline\.botframework|webchat\.botframework", re.I)),
    ("IBM watsonx / Watson Assistant", re.compile(r"watson(?:x|Assistant|\.ai|\.ibm\.com)", re.I)),
]

# AI-provider API key patterns  (name, regex, severity)
AI_KEY_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{48,}"), Severity.CRITICAL),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-]{36,}"), Severity.CRITICAL),
    ("Cohere API Key", re.compile(r"[A-Za-z0-9]{40}(?=.*cohere)", re.I), Severity.CRITICAL),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{34,}"), Severity.CRITICAL),
    ("Replicate Token", re.compile(r"r8_[A-Za-z0-9]{36,}"), Severity.CRITICAL),
    ("Google AI / Vertex Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Azure OpenAI Key", re.compile(r"[0-9a-f]{32}(?=.*(?:openai|azure))", re.I), Severity.CRITICAL),
    ("Together AI Key", re.compile(r"tog-[A-Za-z0-9\-]{40,}"), Severity.CRITICAL),
    ("Groq API Key", re.compile(r"gsk_[A-Za-z0-9]{48,}"), Severity.CRITICAL),
    ("Mistral API Key", re.compile(r"mist-[A-Za-z0-9]{32,}"), Severity.CRITICAL),
    ("xAI (Grok) API Key", re.compile(r"xai-[A-Za-z0-9]{20,}"), Severity.CRITICAL),
]

# Model name patterns (match in JS body) — used for model disclosure check
MODEL_NAME_RE = re.compile(
    r"""(?:['"`])"""
    r"("
    # OpenAI GPT family
    r"gpt-[\d][\w\-\.]*"
    r"|chatgpt-[\w\-\.]+"
    # OpenAI reasoning models (o1, o3, o4-mini, etc.)
    r"|o[1-9][\w\-\.]*"
    # Anthropic Claude
    r"|claude-(?:opus|sonnet|haiku|instant)[\w\-\.]*"
    r"|claude-[\d][\w\-\.]*"
    # Google
    r"|gemini-[\w\-\.]+"
    # Mistral family (mistral, mixtral, codestral, pixtral)
    r"|mistral-[\w\-\.]+"
    r"|mixtral[\w\-\.]*"
    r"|codestral[\w\-\.]*"
    r"|pixtral[\w\-\.]*"
    # Meta Llama
    r"|llama[\-\s]?[\d][\w\-\.]*"
    # Cohere
    r"|command-r[\w\-\.]*"
    # DeepSeek
    r"|deepseek-[\w\-\.]+"
    # Alibaba Qwen
    r"|qwen[\-\s]?[\d][\w\-\.]*"
    # Microsoft Phi
    r"|phi-[\d][\w\-\.]*"
    # xAI Grok
    r"|grok-[\w\-\.]+"
    # Amazon Bedrock models
    r"|amazon\.(?:nova|titan)[\w\-\.]*"
    # Image / multimodal models
    r"|dall-e-[\w\-\.]+"
    r"|stable[\-\s]?diffusion[\w\-\.]*"
    r"|flux[\-\.][\w\-\.]+"
    r"|midjourney[\w\-\.]*"
    r"|ideogram[\w\-\.]*"
    # Audio models
    r"|whisper[\w\-\.]*"
    r"|eleven[\-_]?labs[\w\-\.]*"
    r")"
    r"""(?:['"`])""",
    re.I,
)

# Chat / completion endpoint patterns in JS
CHAT_ENDPOINT_RE = re.compile(
    r"""(?:['"`])"""
    r"(https?://[^\s'\"` ]{5,})"
    r"""(?:['"`])""",
)
CHAT_ENDPOINT_KEYWORDS = re.compile(
    r"(?:chat|completion|generate|inference|predict|prompt|llm|ai/v\d|/v\d/(?:chat|messages|completions))",
    re.I,
)

# System prompt leakage patterns
SYSTEM_PROMPT_RE = re.compile(
    r"""(?:"""
    r"""system[_\- ]?(?:prompt|message|instruction|content)"""
    r"""|role["']?\s*[:=]\s*["']system"""
    r"""|You are (?:a |an )?(?:helpful|friendly|knowledgeable|professional|expert)\b"""
    r"""|<<SYS>>"""
    r"""|<\|system\|>"""
    r"""|SYSTEM:\s"""
    r""")""",
    re.I,
)

# Strings that suggest authentication is required before chat
AUTH_GATE_PATTERNS = re.compile(
    r"(?:login|sign[_\- ]?in|authenticate|auth[_\- ]?required|session[_\- ]?token|bearer)\s*(?:to|before|required|first)",
    re.I,
)

# Strings that suggest payment / billing around AI features
PAYMENT_GATE_PATTERNS = re.compile(
    r"(?:upgrade|subscribe|premium|pro[_\- ]?plan|paid[_\- ]?(?:plan|tier|feature)|billing|pricing|credits?[_\- ]?(?:required|balance|remaining)|usage[_\- ]?limit|quota|pay[_\- ]?per[_\- ]?(?:use|call|request))",
    re.I,
)

# Rate-limit related patterns
RATE_LIMIT_PATTERNS = re.compile(
    r"(?:rate[_\- ]?limit|throttl|too many requests|429|retry[_\- ]?after|x-ratelimit)",
    re.I,
)

# Maximum JS files to fetch
MAX_JS_FILES = 15
# Maximum JS content size to scan (5 MB)
MAX_JS_SIZE = 5 * 1024 * 1024

# ---------------------------------------------------------------------------
# Source-code scanning patterns
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", ".nuxt", ".tox", "egg-info",
}
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}

# Python AI library import patterns
PYTHON_IMPORT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI", re.compile(r"^\s*(?:import\s+openai|from\s+openai[\s.])", re.M)),
    ("Anthropic", re.compile(r"^\s*(?:import\s+anthropic|from\s+anthropic[\s.])", re.M)),
    ("LangChain", re.compile(r"^\s*(?:import\s+langchain|from\s+langchain[\s._])", re.M)),
    ("LlamaIndex", re.compile(r"^\s*(?:import\s+llama_index|from\s+llama_index[\s.])", re.M)),
    ("Cohere", re.compile(r"^\s*(?:import\s+cohere|from\s+cohere[\s.])", re.M)),
    ("Hugging Face", re.compile(
        r"^\s*(?:import\s+transformers|from\s+transformers[\s.]"
        r"|import\s+huggingface_hub|from\s+huggingface_hub[\s.])", re.M)),
    ("Google Generative AI", re.compile(
        r"^\s*(?:import\s+google\.generativeai|from\s+google\.generativeai"
        r"|from\s+vertexai[\s.]|import\s+vertexai)", re.M)),
    ("Amazon Bedrock", re.compile(r"bedrock[_-]?runtime", re.I)),
    ("Mistral", re.compile(r"^\s*(?:import\s+mistralai|from\s+mistralai[\s.])", re.M)),
    ("Groq", re.compile(r"^\s*(?:import\s+groq|from\s+groq[\s.])", re.M)),
    ("Replicate", re.compile(r"^\s*(?:import\s+replicate|from\s+replicate[\s.])", re.M)),
    ("Together AI", re.compile(r"^\s*(?:import\s+together|from\s+together[\s.])", re.M)),
]

# JS/TS import patterns for AI libraries in source files
JS_IMPORT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI", re.compile(r"""(?:require\s*\(\s*['"]openai['"]|from\s+['"]openai['"])""")),
    ("Anthropic", re.compile(r"""(?:require\s*\(\s*['"]@anthropic-ai/sdk['"]|from\s+['"]@anthropic-ai/sdk['"])""")),
    ("LangChain", re.compile(r"""(?:require\s*\(\s*['"]langchain|from\s+['"]langchain)""")),
    ("LlamaIndex", re.compile(r"""(?:require\s*\(\s*['"]llamaindex|from\s+['"]llamaindex)""")),
    ("Cohere", re.compile(r"""(?:require\s*\(\s*['"]cohere-ai['"]|from\s+['"]cohere-ai['"])""")),
    ("Vercel AI SDK", re.compile(r"""(?:require\s*\(\s*['"]ai/|from\s+['"]ai/)""")),
    ("Google Generative AI", re.compile(r"""(?:require\s*\(\s*['"]@google/generative-ai['"]|from\s+['"]@google/generative-ai['"])""")),
    ("Amazon Bedrock", re.compile(r"""(?:require\s*\(\s*['"]@aws-sdk/client-bedrock|from\s+['"]@aws-sdk/client-bedrock)""")),
    ("Azure OpenAI", re.compile(r"""(?:require\s*\(\s*['"]@azure/openai['"]|from\s+['"]@azure/openai['"])""")),
    ("Mistral", re.compile(r"""(?:require\s*\(\s*['"]@mistralai/|from\s+['"]@mistralai/)""")),
    ("Groq", re.compile(r"""(?:require\s*\(\s*['"]groq-sdk['"]|from\s+['"]groq-sdk['"])""")),
    ("Replicate", re.compile(r"""(?:require\s*\(\s*['"]replicate['"]|from\s+['"]replicate['"])""")),
    ("Together AI", re.compile(r"""(?:require\s*\(\s*['"]together-ai['"]|from\s+['"]together-ai['"])""")),
]


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class _ChatbotHTMLParser(HTMLParser):
    """Extract script sources, iframe sources, and relevant HTML attributes."""

    def __init__(self):
        super().__init__()
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self.iframe_srcs: list[str] = []
        self.chat_elements: list[dict] = []
        self._in_inline_script = False
        self._inline_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "script":
            src = attr_dict.get("src", "")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_inline_script = True
                self._inline_buf = []

        elif tag == "iframe":
            src = attr_dict.get("src", "")
            if src:
                self.iframe_srcs.append(src)

        # Look for elements with chatbot-related class/id
        cls = attr_dict.get("class", "")
        eid = attr_dict.get("id", "")
        data_attrs = " ".join(v for k, v in attrs if k.startswith("data-") and v)
        combined = f"{cls} {eid} {data_attrs}".lower()
        chat_keywords = ("chat", "bot", "assistant", "ai-widget", "copilot", "genai")
        if any(kw in combined for kw in chat_keywords):
            self.chat_elements.append({
                "tag": tag,
                "class": cls,
                "id": eid,
            })

    def handle_endtag(self, tag):
        if tag == "script" and self._in_inline_script:
            self._in_inline_script = False
            self.inline_scripts.append("".join(self._inline_buf))

    def handle_data(self, data):
        if self._in_inline_script:
            self._inline_buf.append(data)


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class GenaiModule(BaseModule):
    name = "genai"
    tool_binary = ""
    description = "GenAI / chatbot detection and security analysis"
    target_type = "both"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    # -- entry point --------------------------------------------------------

    def execute(self, target: str) -> list[Finding]:
        source_path = self.config.get("source_path", "")
        target_url = self.config.get("target", "")
        findings: list[Finding] = []
        if source_path and os.path.isdir(source_path):
            findings.extend(self._scan_source(source_path))
        if target_url:
            findings.extend(self._scan_url(target_url))
        return findings

    # -- URL scanning (original behaviour) ----------------------------------

    def _scan_url(self, target: str) -> list[Finding]:
        """Scan a live URL for GenAI / chatbot indicators."""
        body, headers = self._fetch_page(target)
        if body is None:
            return []

        self._save_raw_output(body, "genai-raw.txt")

        parser = _ChatbotHTMLParser()
        try:
            parser.feed(body)
        except Exception:
            pass

        inline_js = "\n".join(parser.inline_scripts)

        # Phase 1: detect presence in HTML + inline JS
        detections: list[dict] = []
        detections.extend(self._detect_widgets_in_html(parser, target))
        detections.extend(self._detect_genai_in_js(inline_js, target, "inline script"))

        # Phase 2: fetch and scan external JS bundles
        js_contents = self._fetch_js_bundles(parser.script_srcs, target)
        for js_url, js_body in js_contents:
            detections.extend(self._detect_genai_in_js(js_body, js_url, f"JS bundle ({js_url})"))

        all_js = inline_js + "\n" + "\n".join(body for _, body in js_contents)

        # Phase 3: security checks
        findings: list[Finding] = []

        if detections:
            findings.append(self._summarize_detections(detections, target))

        findings.extend(self._check_ai_api_keys(all_js, target))
        findings.extend(self._check_system_prompt_leakage(all_js, target))
        findings.extend(self._check_model_disclosure(all_js, target))
        findings.extend(self._check_chat_endpoints(all_js, target))

        if detections:
            findings.extend(self._check_unauthenticated_access(body, all_js, target))
            findings.extend(self._check_missing_payment_gate(body, all_js, detections, target))
            findings.extend(self._check_rate_limiting(all_js, target))
            findings.extend(self._check_transport_security(all_js, target))

        return findings

    def parse_output(self, raw_output: str) -> list[Finding]:
        # Not used — execute() drives everything directly.
        return []

    # -- page fetching ------------------------------------------------------

    def _fetch_page(self, target: str) -> tuple[str | None, dict[str, str]]:
        result = logged_request(target, module_name=self.name)
        if result is None:
            return None, {}
        _status, body, headers = result
        return body, headers

    def _fetch_js_bundles(
        self, script_srcs: list[str], target: str
    ) -> list[tuple[str, str]]:
        """Fetch external JS files and return (url, content) pairs."""
        base_url = target.rstrip("/")
        results: list[tuple[str, str]] = []
        seen: set[str] = set()

        for src in script_srcs[:MAX_JS_FILES]:
            url = self._resolve_url(src, base_url)
            if url in seen:
                continue
            seen.add(url)

            resp = logged_request(url, module_name=self.name, timeout=15)
            if resp is not None:
                _status, js_body, _hdrs = resp
                if len(js_body) <= MAX_JS_SIZE:
                    results.append((url, js_body))

        return results

    @staticmethod
    def _resolve_url(src: str, base_url: str) -> str:
        if src.startswith("//"):
            return "https:" + src
        if src.startswith("/"):
            return base_url + src
        if not src.startswith("http"):
            return base_url + "/" + src
        return src

    # -- detection ----------------------------------------------------------

    def _detect_widgets_in_html(
        self, parser: _ChatbotHTMLParser, target: str
    ) -> list[dict]:
        """Match widget SDKs against script srcs, iframe srcs, and inline scripts."""
        detections: list[dict] = []
        seen_labels: set[str] = set()

        # Check script srcs and iframe srcs
        all_srcs = parser.script_srcs + parser.iframe_srcs
        for src in all_srcs:
            for label, pattern in WIDGET_SDK_PATTERNS:
                if label not in seen_labels and pattern.search(src):
                    detections.append({
                        "label": label,
                        "source": "script/iframe src",
                        "evidence": src,
                    })
                    seen_labels.add(label)

        # Check inline scripts
        inline = "\n".join(parser.inline_scripts)
        for label, pattern in WIDGET_SDK_PATTERNS:
            if label not in seen_labels and pattern.search(inline):
                detections.append({
                    "label": label,
                    "source": "inline script",
                    "evidence": f"Pattern '{label}' matched in inline JS",
                })
                seen_labels.add(label)

        # Check chat-related HTML elements
        if parser.chat_elements:
            for elem in parser.chat_elements[:5]:
                desc = f"<{elem['tag']}"
                if elem["class"]:
                    desc += f" class=\"{elem['class']}\""
                if elem["id"]:
                    desc += f" id=\"{elem['id']}\""
                desc += ">"
                detections.append({
                    "label": "Chat-related HTML element",
                    "source": "HTML attribute",
                    "evidence": desc,
                })

        return detections

    def _detect_genai_in_js(
        self, js_content: str, location: str, source_desc: str
    ) -> list[dict]:
        """Scan JS content for GenAI library / SDK references."""
        detections: list[dict] = []
        if not js_content:
            return detections

        for label, pattern in GENAI_JS_PATTERNS:
            match = pattern.search(js_content)
            if match:
                # Grab a short snippet around the match for evidence
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 30)
                snippet = js_content[start:end].replace("\n", " ").strip()
                detections.append({
                    "label": label,
                    "source": source_desc,
                    "evidence": f"...{snippet}...",
                })

        return detections

    # -- summary finding ----------------------------------------------------

    def _summarize_detections(self, detections: list[dict], target: str) -> Finding:
        """Create a single INFO finding summarizing all detected GenAI / chatbot presence."""
        labels = sorted({d["label"] for d in detections})
        evidence_lines = []
        for d in detections:
            evidence_lines.append(f"[{d['label']}] ({d['source']}): {d['evidence']}")

        return Finding(
            title=f"GenAI / chatbot presence detected ({len(labels)} indicator{'s' if len(labels) != 1 else ''})",
            severity=Severity.INFO,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                f"The following GenAI or chatbot indicators were found: {', '.join(labels)}. "
                "These features should be reviewed for authentication requirements, input/output "
                "filtering, rate limiting, and cost controls."
            ),
            location=target,
            evidence="\n".join(evidence_lines[:20]),
            metadata={"detected_labels": labels},
        )

    # -- security checks ----------------------------------------------------

    def _check_ai_api_keys(self, js_content: str, target: str) -> list[Finding]:
        """Scan JS for exposed AI-provider API keys."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for key_name, pattern, severity in AI_KEY_PATTERNS:
            for match in pattern.finditer(js_content):
                matched_text = match.group(0)
                dedup = f"{key_name}:{matched_text[:12]}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                if len(matched_text) > 12:
                    redacted = matched_text[:6] + "..." + matched_text[-4:]
                else:
                    redacted = matched_text[:4] + "..."

                findings.append(Finding(
                    title=f"{key_name} exposed in client-side JavaScript",
                    severity=severity,
                    category=Category.SECRET,
                    source=self.name,
                    description=(
                        f"A pattern matching {key_name} was found in client-side code. "
                        "Anyone visiting the page can extract this key and use it to make "
                        "API calls at the owner's expense or access sensitive data."
                    ),
                    location=target,
                    evidence=f"Redacted: {redacted}",
                    remediation=(
                        "Move the API key to a backend proxy. Never ship AI-provider "
                        "secrets to the browser. Rotate the key immediately if it was "
                        "ever served publicly."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
                    metadata={"key_type": key_name},
                ))

        return findings

    def _check_system_prompt_leakage(self, js_content: str, target: str) -> list[Finding]:
        """Look for system prompt / instruction text shipped to the client."""
        findings: list[Finding] = []
        matches = list(SYSTEM_PROMPT_RE.finditer(js_content))
        if not matches:
            return findings

        snippets: list[str] = []
        for m in matches[:5]:
            start = max(0, m.start() - 40)
            end = min(len(js_content), m.end() + 120)
            snippet = js_content[start:end].replace("\n", " ").strip()
            snippets.append(f"...{snippet}...")

        findings.append(Finding(
            title="Possible system prompt or LLM instructions in client-side code",
            severity=Severity.MEDIUM,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                "Patterns resembling LLM system prompts or role instructions were "
                "found in JavaScript served to the browser. Exposing system prompts "
                "lets attackers understand guardrails and craft targeted prompt "
                "injection attacks."
            ),
            location=target,
            evidence="\n".join(snippets),
            remediation=(
                "Keep system prompts on the server side. Send only user messages "
                "from the client and prepend the system prompt in the backend before "
                "calling the LLM API."
            ),
            reference="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ))

        return findings

    def _check_model_disclosure(self, js_content: str, target: str) -> list[Finding]:
        """Flag AI model names hardcoded in client JS."""
        models_found: set[str] = set()
        for m in MODEL_NAME_RE.finditer(js_content):
            models_found.add(m.group(1).lower())

        if not models_found:
            return []

        return [Finding(
            title=f"AI model name(s) disclosed in client-side code ({len(models_found)})",
            severity=Severity.LOW,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                f"The following model identifiers were found in JavaScript: "
                f"{', '.join(sorted(models_found))}. Disclosing model names helps "
                "attackers tailor prompt injection payloads to the specific model's "
                "weaknesses and reveals technology choices."
            ),
            location=target,
            evidence=", ".join(sorted(models_found)),
            remediation=(
                "Reference models by an internal alias on the client side and "
                "resolve to the actual model name on the server."
            ),
        )]

    def _check_chat_endpoints(self, js_content: str, target: str) -> list[Finding]:
        """Detect chat / completion API endpoints embedded in client JS."""
        endpoints: set[str] = set()
        for m in CHAT_ENDPOINT_RE.finditer(js_content):
            url = m.group(1)
            if CHAT_ENDPOINT_KEYWORDS.search(url):
                # Skip well-known public API docs / marketing pages
                parsed = urlparse(url)
                if parsed.netloc and "docs." not in parsed.netloc:
                    endpoints.add(url)

        if not endpoints:
            return []

        return [Finding(
            title=f"Chat / AI backend endpoint(s) exposed in client code ({len(endpoints)})",
            severity=Severity.MEDIUM,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                "Backend URLs for chat or AI completion were found in JavaScript. "
                "Exposed endpoints can be called directly, bypassing any "
                "client-side guardrails, input filters, or usage tracking."
            ),
            location=target,
            evidence="\n".join(sorted(endpoints)[:10]),
            remediation=(
                "Proxy AI requests through your own backend with authentication "
                "and rate limiting. Avoid embedding direct API URLs in client code."
            ),
        )]

    def _check_unauthenticated_access(
        self, body: str, js_content: str, target: str
    ) -> list[Finding]:
        """Flag when a chatbot / AI feature appears accessible without login."""
        combined = body + "\n" + js_content

        # If we find signs that auth is required, this is fine
        if AUTH_GATE_PATTERNS.search(combined):
            return []

        return [Finding(
            title="GenAI / chatbot feature appears accessible without authentication",
            severity=Severity.MEDIUM,
            category=Category.AUTH,
            source=self.name,
            description=(
                "A chatbot or GenAI feature was detected on a page with no apparent "
                "authentication requirement. Unauthenticated access means anyone can "
                "interact with the AI, potentially abusing it for prompt injection, "
                "data extraction, or running up API costs."
            ),
            location=target,
            evidence="No login / authentication gate detected around AI feature",
            remediation=(
                "Require user authentication before allowing access to AI-powered "
                "features. At minimum, gate behind a session so abuse can be traced "
                "and throttled per-user."
            ),
            reference="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        )]

    def _check_missing_payment_gate(
        self,
        body: str,
        js_content: str,
        detections: list[dict],
        target: str,
    ) -> list[Finding]:
        """Flag LLM-backed features that appear to have no payment or usage gate.

        Third-party chat widgets (Intercom, Drift, etc.) are typically paid by the
        site owner via subscription — so a missing paywall on the *user* side is
        expected and not flagged.  But first-party LLM integrations (OpenAI,
        Anthropic, LangChain, etc.) incur per-call costs that should be gated.
        """
        # Only flag if we detected an LLM / GenAI SDK (not just a SaaS widget)
        genai_labels = {d["label"] for d in detections}
        saas_widget_labels = {label for label, _ in WIDGET_SDK_PATTERNS}
        llm_detected = genai_labels - saas_widget_labels

        if not llm_detected:
            return []

        combined = body + "\n" + js_content
        if PAYMENT_GATE_PATTERNS.search(combined):
            return []

        return [Finding(
            title="LLM-backed feature has no visible payment or usage gate",
            severity=Severity.MEDIUM,
            category=Category.AUTH,
            source=self.name,
            description=(
                f"LLM integration detected ({', '.join(sorted(llm_detected))}) with "
                "no apparent payment, subscription, or credit-balance requirement. "
                "Each AI API call costs money; without a gate, anonymous or free-tier "
                "users can generate unbounded costs."
            ),
            location=target,
            evidence="No pricing, credits, or subscription gate detected around AI feature",
            remediation=(
                "Implement usage controls for LLM-powered features: require payment, "
                "enforce credit/quota limits, or restrict to authenticated paid-tier "
                "users. Monitor spend with provider-side budget alerts."
            ),
        )]

    def _check_rate_limiting(self, js_content: str, target: str) -> list[Finding]:
        """Flag absence of any rate-limiting references in chat-related JS."""
        if RATE_LIMIT_PATTERNS.search(js_content):
            return []

        return [Finding(
            title="No rate-limiting indicators found for AI feature",
            severity=Severity.LOW,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                "No client-side references to rate limiting, throttling, or retry-after "
                "logic were found for the detected AI feature. Without rate limiting, "
                "an attacker can send high-volume requests to exhaust API quotas or "
                "inflate costs."
            ),
            location=target,
            evidence="No rate-limit handling detected in JS bundles",
            remediation=(
                "Implement server-side rate limiting on AI endpoints (per-user and "
                "global). Return 429 responses with Retry-After headers. Add "
                "client-side handling for rate-limit responses."
            ),
        )]

    def _check_transport_security(self, js_content: str, target: str) -> list[Finding]:
        """Flag chat/AI endpoints or WebSocket connections using plain HTTP/WS."""
        findings: list[Finding] = []

        # Check for http:// endpoints in chat-related URLs
        insecure_urls: set[str] = set()
        for m in CHAT_ENDPOINT_RE.finditer(js_content):
            url = m.group(1)
            if url.startswith("http://") and CHAT_ENDPOINT_KEYWORDS.search(url):
                insecure_urls.add(url)

        # Check for ws:// (unencrypted WebSocket)
        ws_re = re.compile(r"""(?:['"`])(ws://[^\s'"`]+)(?:['"`])""")
        for m in ws_re.finditer(js_content):
            ws_url = m.group(1)
            if any(kw in ws_url.lower() for kw in ("chat", "bot", "ai", "llm", "stream", "message")):
                insecure_urls.add(ws_url)

        if not insecure_urls:
            return findings

        findings.append(Finding(
            title="AI / chat traffic sent over insecure transport",
            severity=Severity.HIGH,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                "Chat or AI endpoints use unencrypted HTTP or WebSocket (ws://) "
                "connections. Conversation content, user inputs, and potentially "
                "API keys are exposed to network-level attackers."
            ),
            location=target,
            evidence="\n".join(sorted(insecure_urls)[:5]),
            remediation="Use HTTPS and WSS (wss://) for all AI and chat traffic.",
        ))

        return findings

    # -- source-code scanning -----------------------------------------------

    def _scan_source(self, source_path: str) -> list[Finding]:
        """Scan local source files for GenAI usage patterns and security issues."""
        findings: list[Finding] = []
        detections: list[dict] = []
        prompt_hits: list[tuple[str, str]] = []  # (rel_path, snippet)
        models_by_file: dict[str, set[str]] = {}  # rel_path -> model names

        for rel_path, content in self._walk_source_files(source_path):
            detections.extend(self._detect_source_imports(rel_path, content))
            findings.extend(self._check_source_api_keys(content, rel_path))

            for m in SYSTEM_PROMPT_RE.finditer(content):
                start = max(0, m.start() - 40)
                end = min(len(content), m.end() + 120)
                snippet = content[start:end].replace("\n", " ").strip()
                prompt_hits.append((rel_path, snippet))

            for m in MODEL_NAME_RE.finditer(content):
                model = m.group(1).lower()
                models_by_file.setdefault(rel_path, set()).add(model)

        # Save raw output
        raw_lines = [f"[{d['label']}] {d['source']}: {d['evidence']}" for d in detections]
        self._save_raw_output(
            "\n".join(raw_lines) or "(no GenAI indicators found in source)",
            "genai-source-raw.txt",
        )

        if detections:
            findings.insert(0, self._summarize_detections(detections, source_path))

        if prompt_hits:
            snippets = [f"{path}: ...{snip}..." for path, snip in prompt_hits[:10]]
            findings.append(Finding(
                title=(
                    f"System prompts or LLM instructions in source code "
                    f"({len(prompt_hits)} occurrence{'s' if len(prompt_hits) != 1 else ''})"
                ),
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=(
                    "Patterns resembling LLM system prompts or role instructions were "
                    "found in source files. Exposed system prompts let attackers "
                    "understand guardrails and craft targeted prompt injection attacks."
                ),
                location=source_path,
                evidence="\n".join(snippets),
                remediation=(
                    "Store system prompts in environment variables or a secrets "
                    "manager rather than hardcoding them. Ensure the repository is "
                    "private and prompts are not shipped to the client."
                ),
                reference="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ))

        if models_by_file:
            all_models: set[str] = set()
            evidence_lines: list[str] = []
            for path, models in sorted(models_by_file.items()):
                all_models.update(models)
                evidence_lines.append(f"{path}: {', '.join(sorted(models))}")
            findings.append(Finding(
                title=f"AI model name(s) hardcoded in source ({len(all_models)})",
                severity=Severity.LOW,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=(
                    f"The following model identifiers were found in source code: "
                    f"{', '.join(sorted(all_models))}. Hardcoded model names reveal "
                    "technology choices and help attackers tailor prompt injection "
                    "payloads to specific model weaknesses."
                ),
                location=source_path,
                evidence="\n".join(evidence_lines[:15]),
                remediation=(
                    "Reference models by an internal alias or environment variable "
                    "and resolve to the actual model name at runtime."
                ),
            ))

        return findings

    def _walk_source_files(self, source_path: str):
        """Yield (rel_path, content) for source files in the directory tree."""
        for dirpath, dirnames, filenames in os.walk(source_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SOURCE_EXTENSIONS:
                    continue
                filepath = os.path.join(dirpath, filename)
                try:
                    if os.path.getsize(filepath) > MAX_JS_SIZE:
                        continue
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue
                yield os.path.relpath(filepath, source_path), content

    def _detect_source_imports(self, rel_path: str, content: str) -> list[dict]:
        """Detect AI library imports in a source file."""
        detections: list[dict] = []
        seen_labels: set[str] = set()

        if rel_path.endswith(".py"):
            patterns = PYTHON_IMPORT_PATTERNS
        elif rel_path.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
            patterns = JS_IMPORT_PATTERNS
        else:
            return detections

        for label, pattern in patterns:
            if label in seen_labels:
                continue
            match = pattern.search(content)
            if match:
                seen_labels.add(label)
                line_num = content[:match.start()].count("\n") + 1
                nl = content.find("\n", match.start())
                line = content[match.start():nl if nl != -1 else len(content)].strip()
                detections.append({
                    "label": label,
                    "source": f"source file ({rel_path}:{line_num})",
                    "evidence": line[:120],
                })

        return detections

    def _check_source_api_keys(self, content: str, rel_path: str) -> list[Finding]:
        """Scan a source file for exposed AI-provider API keys."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for key_name, pattern, severity in AI_KEY_PATTERNS:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                dedup = f"{key_name}:{matched_text[:12]}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                line_num = content[:match.start()].count("\n") + 1
                if len(matched_text) > 12:
                    redacted = matched_text[:6] + "..." + matched_text[-4:]
                else:
                    redacted = matched_text[:4] + "..."

                findings.append(Finding(
                    title=f"{key_name} found in source code",
                    severity=severity,
                    category=Category.SECRET,
                    source=self.name,
                    description=(
                        f"A pattern matching {key_name} was found in {rel_path} "
                        f"at line {line_num}. If committed to version control, this "
                        "key may be exposed. Rotate the key immediately if it was "
                        "ever pushed to a remote repository."
                    ),
                    location=f"{rel_path}:{line_num}",
                    evidence=f"Redacted: {redacted}",
                    remediation=(
                        "Move the API key to an environment variable or secrets "
                        "manager. Never commit AI-provider secrets to source control. "
                        "Rotate the key immediately."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
                    metadata={"key_type": key_name},
                ))

        return findings
