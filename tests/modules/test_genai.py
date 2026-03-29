"""Tests for the GenAI / chatbot detection module."""

from webscan.models import Category, Severity
from webscan.modules.genai import (
    GenaiModule,
    _ChatbotHTMLParser,
    WIDGET_SDK_PATTERNS,
    GENAI_JS_PATTERNS,
)


def _make_module(target="https://example.com"):
    return GenaiModule({"target": target})


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------


class TestChatbotHTMLParser:
    def test_extracts_script_srcs(self):
        html = '<script src="https://cdn.example.com/app.js"></script>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert "https://cdn.example.com/app.js" in parser.script_srcs

    def test_extracts_inline_scripts(self):
        html = "<script>var x = 1;</script>"
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert "var x = 1;" in parser.inline_scripts

    def test_extracts_iframe_srcs(self):
        html = '<iframe src="https://chat.example.com/widget"></iframe>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert "https://chat.example.com/widget" in parser.iframe_srcs

    def test_detects_chat_elements_by_class(self):
        html = '<div class="chat-widget-container"></div>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert len(parser.chat_elements) == 1
        assert parser.chat_elements[0]["class"] == "chat-widget-container"

    def test_detects_chat_elements_by_id(self):
        html = '<div id="ai-assistant-panel"></div>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert len(parser.chat_elements) == 1
        assert parser.chat_elements[0]["id"] == "ai-assistant-panel"

    def test_detects_chatbot_in_data_attrs(self):
        html = '<div data-widget="chatbot-v2"></div>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert len(parser.chat_elements) == 1

    def test_ignores_non_chat_elements(self):
        html = '<div class="header-nav"></div><div id="footer"></div>'
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert len(parser.chat_elements) == 0

    def test_multiple_scripts_and_iframes(self):
        html = (
            '<script src="/a.js"></script>'
            '<script src="/b.js"></script>'
            '<iframe src="https://x.com"></iframe>'
        )
        parser = _ChatbotHTMLParser()
        parser.feed(html)
        assert len(parser.script_srcs) == 2
        assert len(parser.iframe_srcs) == 1


# ---------------------------------------------------------------------------
# Widget SDK detection
# ---------------------------------------------------------------------------


class TestWidgetDetection:
    def test_intercom_script(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<script src="https://widget.intercom.io/widget/abc123"></script>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Intercom" in labels

    def test_drift_script(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<script src="https://js.driftcdn.com/include/abc.js"></script>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Drift" in labels

    def test_tidio_script(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<script src="https://code.tidio.co/abc.js"></script>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Tidio" in labels

    def test_tawk_iframe(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<iframe src="https://embed.tawk.to/abc/default"></iframe>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Tawk.to" in labels

    def test_zendesk_web_widget(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed(
            '<script id="ze-snippet" '
            'src="https://static.zdassets.com/ekr/snippet.js?key=zendesk-web-widget-abc">'
            "</script>"
        )
        # zendesk pattern also matches inline
        parser2 = _ChatbotHTMLParser()
        parser2.feed("<script>zopim.init();</script>")
        detections = module._detect_widgets_in_html(parser2, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Zendesk Chat" in labels

    def test_chatwoot_inline(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<script>window.chatwootSDK.run({});</script>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        labels = [d["label"] for d in detections]
        assert "Chatwoot" in labels

    def test_no_widgets_on_clean_page(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed("<html><body><p>Hello</p></body></html>")
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        assert len(detections) == 0

    def test_chat_html_elements_detected(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed('<div id="chatbot-container" class="ai-widget"></div>')
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        assert any(d["label"] == "Chat-related HTML element" for d in detections)

    def test_deduplicates_same_widget(self):
        module = _make_module()
        parser = _ChatbotHTMLParser()
        parser.feed(
            '<script src="https://widget.intercom.io/a.js"></script>'
            '<script src="https://widget.intercom.io/b.js"></script>'
        )
        detections = module._detect_widgets_in_html(parser, "https://example.com")
        intercom_count = sum(1 for d in detections if d["label"] == "Intercom")
        assert intercom_count == 1


# ---------------------------------------------------------------------------
# GenAI SDK detection in JS
# ---------------------------------------------------------------------------


class TestGenAIJSDetection:
    def test_openai_client(self):
        module = _make_module()
        js = 'const client = new OpenAIApi(config);'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "OpenAI client" in labels

    def test_anthropic_client(self):
        module = _make_module()
        js = 'import { AnthropicClient } from "anthropic";'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "Anthropic client" in labels

    def test_langchain(self):
        module = _make_module()
        js = 'import { ChatOpenAI } from "langchain/chat_models";'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "LangChain" in labels

    def test_vercel_ai_sdk(self):
        module = _make_module()
        js = 'const { useChat } = require("ai/react");'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "Vercel AI SDK" in labels

    def test_dialogflow(self):
        module = _make_module()
        js = '<script src="https://www.gstatic.com/dialogflow/messenger.js"></script>'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "Dialogflow" in labels

    def test_hugging_face(self):
        module = _make_module()
        js = 'const hf = new HfInference(token);'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        labels = [d["label"] for d in detections]
        assert "Hugging Face" in labels

    def test_no_genai_in_clean_js(self):
        module = _make_module()
        js = 'function add(a, b) { return a + b; }'
        detections = module._detect_genai_in_js(js, "https://example.com", "inline")
        assert len(detections) == 0

    def test_empty_js(self):
        module = _make_module()
        detections = module._detect_genai_in_js("", "https://example.com", "inline")
        assert len(detections) == 0


# ---------------------------------------------------------------------------
# Summary finding
# ---------------------------------------------------------------------------


class TestDetectionSummary:
    def test_summary_finding_created(self):
        module = _make_module()
        detections = [
            {"label": "Intercom", "source": "script src", "evidence": "intercom.io/widget"},
            {"label": "OpenAI client", "source": "JS bundle", "evidence": "...OpenAI..."},
        ]
        finding = module._summarize_detections(detections, "https://example.com")
        assert finding.severity == Severity.INFO
        assert "2 indicators" in finding.title
        assert "Intercom" in finding.description
        assert "OpenAI client" in finding.description

    def test_single_detection_singular(self):
        module = _make_module()
        detections = [
            {"label": "Drift", "source": "script src", "evidence": "drift.com/widget"},
        ]
        finding = module._summarize_detections(detections, "https://example.com")
        assert "1 indicator" in finding.title


# ---------------------------------------------------------------------------
# AI API key detection
# ---------------------------------------------------------------------------


class TestAIAPIKeys:
    def test_openai_key(self):
        module = _make_module()
        # Use a realistic-length key pattern
        js = 'const key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDE";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        key_findings = [f for f in findings if "OpenAI" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.CRITICAL
        assert key_findings[0].category == Category.SECRET

    def test_anthropic_key(self):
        module = _make_module()
        js = 'const key = "sk-ant-abcdefghijklmnopqrstuvwxyz123456789a";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        key_findings = [f for f in findings if "Anthropic" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.CRITICAL

    def test_hugging_face_token(self):
        module = _make_module()
        js = 'const token = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        key_findings = [f for f in findings if "Hugging Face" in f.title]
        assert len(key_findings) == 1

    def test_groq_key(self):
        module = _make_module()
        js = 'const key = "gsk_' + "a" * 48 + '";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        key_findings = [f for f in findings if "Groq" in f.title]
        assert len(key_findings) == 1

    def test_redaction(self):
        module = _make_module()
        js = 'const key = "sk-ant-abcdefghijklmnopqrstuvwxyz123456789a";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        # The full key should NOT appear in evidence
        assert "sk-ant-abcdefghijklmnopqrstuvwxyz123456789a" not in findings[0].evidence
        assert "Redacted" in findings[0].evidence

    def test_no_keys_clean_js(self):
        module = _make_module()
        js = 'function doSomething() { return 42; }'
        findings = module._check_ai_api_keys(js, "https://example.com")
        assert len(findings) == 0

    def test_deduplication(self):
        module = _make_module()
        key = "sk-ant-abcdefghijklmnopqrstuvwxyz123456789a"
        js = f'var a = "{key}"; var b = "{key}";'
        findings = module._check_ai_api_keys(js, "https://example.com")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# System prompt leakage
# ---------------------------------------------------------------------------


class TestSystemPromptLeakage:
    def test_system_prompt_pattern(self):
        module = _make_module()
        js = 'const messages = [{role: "system", content: "You are a helpful assistant"}];'
        findings = module._check_system_prompt_leakage(js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_you_are_a_pattern(self):
        module = _make_module()
        js = 'const systemPrompt = "You are a helpful customer support agent for Acme Corp.";'
        findings = module._check_system_prompt_leakage(js, "https://example.com")
        assert len(findings) == 1

    def test_system_message_variable(self):
        module = _make_module()
        js = 'const system_prompt = "Answer questions about our products.";'
        findings = module._check_system_prompt_leakage(js, "https://example.com")
        assert len(findings) == 1

    def test_no_system_prompt(self):
        module = _make_module()
        js = 'const msg = "Hello, how can I help you today?";'
        findings = module._check_system_prompt_leakage(js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Model disclosure
# ---------------------------------------------------------------------------


class TestModelDisclosure:
    def test_gpt4_detected(self):
        module = _make_module()
        js = 'const model = "gpt-4-turbo";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1
        assert "gpt-4-turbo" in findings[0].evidence

    def test_gpt_4_1_mini(self):
        module = _make_module()
        js = 'const model = "gpt-4.1-mini";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1
        assert "gpt-4.1-mini" in findings[0].evidence

    def test_gpt_5_4(self):
        module = _make_module()
        js = 'const model = "gpt-5.4";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1
        assert "gpt-5.4" in findings[0].evidence

    def test_gpt_4o_mini(self):
        module = _make_module()
        js = 'const model = "gpt-4o-mini";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_chatgpt_4o_latest(self):
        module = _make_module()
        js = 'const model = "chatgpt-4o-latest";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_o3_mini(self):
        module = _make_module()
        js = 'const model = "o3-mini";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_o4_mini(self):
        module = _make_module()
        js = 'const model = "o4-mini-high";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_claude_detected(self):
        module = _make_module()
        js = 'const model = "claude-sonnet-4-20250514";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_gemini_detected(self):
        module = _make_module()
        js = 'const model = "gemini-1.5-pro";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_deepseek_detected(self):
        module = _make_module()
        js = 'const model = "deepseek-r1";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_qwen_detected(self):
        module = _make_module()
        js = 'const model = "qwen2.5-72b-instruct";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_grok_detected(self):
        module = _make_module()
        js = 'const model = "grok-2";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_phi_detected(self):
        module = _make_module()
        js = 'const model = "phi-4";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_llama_detected(self):
        module = _make_module()
        js = 'const model = "llama-4-scout";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_codestral_detected(self):
        module = _make_module()
        js = 'const model = "codestral-latest";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_flux_detected(self):
        module = _make_module()
        js = 'const model = "flux-1.1-pro";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1

    def test_multiple_models(self):
        module = _make_module()
        js = 'const models = ["gpt-4", "claude-sonnet-4-20250514"];'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 1  # Single finding listing all
        assert "2" in findings[0].title

    def test_no_models(self):
        module = _make_module()
        js = 'const version = "1.0.0";'
        findings = module._check_model_disclosure(js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Chat endpoint detection
# ---------------------------------------------------------------------------


class TestChatEndpoints:
    def test_chat_completion_url(self):
        module = _make_module()
        js = 'const url = "https://api.example.com/v1/chat/completions";'
        findings = module._check_chat_endpoints(js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_custom_ai_endpoint(self):
        module = _make_module()
        js = 'fetch("https://backend.example.com/ai/v1/generate", {method: "POST"});'
        findings = module._check_chat_endpoints(js, "https://example.com")
        assert len(findings) == 1

    def test_docs_url_ignored(self):
        module = _make_module()
        js = 'const docsUrl = "https://docs.openai.com/v1/chat/completions";'
        findings = module._check_chat_endpoints(js, "https://example.com")
        assert len(findings) == 0

    def test_no_endpoints(self):
        module = _make_module()
        js = 'fetch("https://api.example.com/users");'
        findings = module._check_chat_endpoints(js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Unauthenticated access
# ---------------------------------------------------------------------------


class TestUnauthenticatedAccess:
    def test_no_auth_gate_flagged(self):
        module = _make_module()
        body = "<html><body><div id='chatbot'></div></body></html>"
        js = "function sendMessage(msg) { fetch('/chat', {body: msg}); }"
        findings = module._check_unauthenticated_access(body, js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == Category.AUTH

    def test_auth_gate_present_no_finding(self):
        module = _make_module()
        body = "<html><body>Please login to access the assistant</body></html>"
        js = "if (!session_token) { redirect('/login'); } // authenticate first"
        findings = module._check_unauthenticated_access(body, js, "https://example.com")
        assert len(findings) == 0

    def test_sign_in_required(self):
        module = _make_module()
        body = "<html><body>Sign in required before using chat</body></html>"
        js = ""
        findings = module._check_unauthenticated_access(body, js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Missing payment gate
# ---------------------------------------------------------------------------


class TestMissingPaymentGate:
    def test_llm_without_payment_flagged(self):
        module = _make_module()
        # Detections include an LLM SDK, not just a SaaS widget
        detections = [
            {"label": "OpenAI client", "source": "JS", "evidence": "...OpenAI..."},
        ]
        body = "<html><body>Chat with our AI</body></html>"
        js = "const client = new OpenAI();"
        findings = module._check_missing_payment_gate(body, js, detections, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "payment" in findings[0].title.lower() or "payment" in findings[0].description.lower()

    def test_saas_widget_not_flagged(self):
        """SaaS widgets (Intercom etc.) are paid by site owner — no paywall needed."""
        module = _make_module()
        detections = [
            {"label": "Intercom", "source": "script src", "evidence": "intercom.io"},
        ]
        body = "<html><body>Chat with us</body></html>"
        js = ""
        findings = module._check_missing_payment_gate(body, js, detections, "https://example.com")
        assert len(findings) == 0

    def test_payment_gate_present(self):
        module = _make_module()
        detections = [
            {"label": "OpenAI client", "source": "JS", "evidence": "...OpenAI..."},
        ]
        body = "<html><body>Upgrade to premium plan to use AI features</body></html>"
        js = "if (credits_remaining <= 0) { showUpgradeModal(); }"
        findings = module._check_missing_payment_gate(body, js, detections, "https://example.com")
        assert len(findings) == 0

    def test_mixed_widget_and_llm(self):
        """When both a SaaS widget and LLM SDK are present, the LLM triggers the check."""
        module = _make_module()
        detections = [
            {"label": "Intercom", "source": "script src", "evidence": "intercom.io"},
            {"label": "LangChain", "source": "JS", "evidence": "...langchain..."},
        ]
        body = "<html><body>AI-powered support</body></html>"
        js = ""
        findings = module._check_missing_payment_gate(body, js, detections, "https://example.com")
        assert len(findings) == 1
        assert "LangChain" in findings[0].description


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_no_rate_limit_flagged(self):
        module = _make_module()
        js = "function send(msg) { fetch('/chat', {body: msg}); }"
        findings = module._check_rate_limiting(js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_rate_limit_present(self):
        module = _make_module()
        js = "if (response.status === 429) { showError('Too many requests, rate_limit exceeded'); }"
        findings = module._check_rate_limiting(js, "https://example.com")
        assert len(findings) == 0

    def test_retry_after_present(self):
        module = _make_module()
        js = "const retryMs = parseInt(headers['retry-after']) * 1000;"
        findings = module._check_rate_limiting(js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Transport security
# ---------------------------------------------------------------------------


class TestTransportSecurity:
    def test_http_chat_endpoint_flagged(self):
        module = _make_module()
        js = 'const endpoint = "http://api.example.com/chat/send";'
        findings = module._check_transport_security(js, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ws_chat_endpoint_flagged(self):
        module = _make_module()
        js = 'const ws = new WebSocket("ws://api.example.com/chat/stream");'
        findings = module._check_transport_security(js, "https://example.com")
        assert len(findings) == 1

    def test_https_endpoint_clean(self):
        module = _make_module()
        js = 'const endpoint = "https://api.example.com/chat/send";'
        findings = module._check_transport_security(js, "https://example.com")
        assert len(findings) == 0

    def test_wss_endpoint_clean(self):
        module = _make_module()
        js = 'const ws = new WebSocket("wss://api.example.com/chat/stream");'
        findings = module._check_transport_security(js, "https://example.com")
        assert len(findings) == 0

    def test_unrelated_http_url_not_flagged(self):
        module = _make_module()
        js = 'fetch("http://api.example.com/users/list");'
        findings = module._check_transport_security(js, "https://example.com")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


class TestModuleMetadata:
    def test_module_name(self):
        module = _make_module()
        assert module.name == "genai"

    def test_built_in(self):
        module = _make_module()
        ok, info = module.check_installed()
        assert ok is True
        assert info == "built-in"

    def test_version(self):
        module = _make_module()
        assert module.get_version() == "built-in"
