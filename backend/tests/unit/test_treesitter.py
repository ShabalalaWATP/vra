"""Tests for Tree-sitter integration (runs with or without tree-sitter installed)."""

from app.analysis.treesitter import parse_file, is_available


def test_parse_python_file():
    code = '''
import os
from pathlib import Path

def process_request(request):
    user_input = request.args.get("query")
    result = os.system(user_input)
    return result

class AuthManager:
    def authenticate(self, token):
        return verify_jwt(token)

    def authorize(self, user, resource):
        return check_permissions(user, resource)
'''
    analysis = parse_file(code, "python")

    assert analysis.language == "python"
    assert analysis.line_count > 0

    func_names = [s.name for s in analysis.symbols if s.kind == "function"]
    assert "process_request" in func_names

    class_names = [s.name for s in analysis.symbols if s.kind == "class"]
    assert "AuthManager" in class_names

    method_names = [s.name for s in analysis.symbols if s.kind == "method"]
    assert "authenticate" in method_names
    assert "authorize" in method_names

    # Check security tagging
    process_fn = next(s for s in analysis.symbols if s.name == "process_request")
    assert process_fn.tags.get("command_exec") or process_fn.tags.get("input_handling")


def test_parse_javascript_file():
    code = '''
import express from "express";
import { readFile } from "fs";

const app = express();

function handleUpload(req, res) {
    const filename = req.body.filename;
    readFile(filename, (err, data) => {
        res.send(data);
    });
}

class UserController {
    async getUser(req, res) {
        const id = req.params.id;
        const user = await db.query("SELECT * FROM users WHERE id = " + id);
        res.json(user);
    }
}

app.post("/upload", handleUpload);
'''
    analysis = parse_file(code, "javascript")

    assert analysis.language == "javascript"

    func_names = [s.name for s in analysis.symbols if s.kind == "function"]
    assert "handleUpload" in func_names

    class_names = [s.name for s in analysis.symbols if s.kind == "class"]
    assert "UserController" in class_names

    assert len(analysis.imports) >= 1
    assert len(analysis.routes) >= 1


def test_parse_unsupported_language():
    """Should gracefully handle unsupported languages."""
    code = "some random content"
    analysis = parse_file(code, "brainfuck")
    assert analysis.language == "brainfuck"
    # Should not crash, may return empty symbols
