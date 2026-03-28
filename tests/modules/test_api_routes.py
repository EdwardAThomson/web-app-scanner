"""Tests for the API routes module."""

import os
import tempfile

from webscan.models import Category, Severity
from webscan.modules.api_routes import ApiRoutesModule


def _make_module(source_path="", target=""):
    return ApiRoutesModule({
        "source_path": source_path,
        "target": target,
    })


class TestRouteDiscovery:
    def test_express_routes(self, tmp_path):
        (tmp_path / "app.js").write_text("""
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => { res.json([]); });
app.post('/api/users', (req, res) => { res.json({}); });
app.get('/api/health', (req, res) => { res.json({ok: true}); });
app.delete('/api/users/:id', (req, res) => { res.json({}); });
""")
        module = _make_module(source_path=str(tmp_path))
        routes = module._discover_routes(str(tmp_path))
        assert len(routes) == 4
        methods = [r[0].upper() for r in routes]
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods
        paths = [r[1] for r in routes]
        assert "/api/users" in paths
        assert "/api/health" in paths

    def test_fastapi_routes(self, tmp_path):
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/items")
def list_items():
    return []

@app.post("/api/items")
def create_item():
    return {}

@router.get("/api/health")
def health():
    return {"ok": True}
""")
        module = _make_module(source_path=str(tmp_path))
        routes = module._discover_routes(str(tmp_path))
        assert len(routes) == 3
        paths = [r[1] for r in routes]
        assert "/api/items" in paths
        assert "/api/health" in paths

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "express"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("app.get('/internal', () => {})")
        (tmp_path / "app.js").write_text("app.get('/real', () => {})")

        module = _make_module(source_path=str(tmp_path))
        routes = module._discover_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0][1] == "/real"

    def test_execute_returns_info_findings(self, tmp_path):
        (tmp_path / "app.js").write_text("app.get('/api/test', () => {})")
        module = _make_module(source_path=str(tmp_path))
        findings = module.execute(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.AUTH
        assert "GET" in findings[0].metadata["method"]

    def test_no_source_path(self):
        module = _make_module()
        findings = module.execute("")
        assert findings == []

    def test_empty_project(self, tmp_path):
        module = _make_module(source_path=str(tmp_path))
        findings = module.execute(str(tmp_path))
        assert findings == []
