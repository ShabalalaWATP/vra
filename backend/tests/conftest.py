"""Test configuration and fixtures."""

import pytest


@pytest.fixture
def sample_repo(tmp_path):
    """Create a minimal sample repo for testing."""
    # Python file
    (tmp_path / "app.py").write_text(
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        '@app.route("/login", methods=["POST"])\n'
        'def login():\n'
        '    username = request.form["username"]\n'
        '    password = request.form["password"]\n'
        '    return "ok"\n'
    )

    # JS file
    (tmp_path / "server.js").write_text(
        'const express = require("express");\n'
        'const app = express();\n'
        'app.get("/api/users", (req, res) => {\n'
        '  const id = req.query.id;\n'
        '  res.json({ id });\n'
        '});\n'
    )

    # Config
    (tmp_path / "config.py").write_text(
        'SECRET_KEY = "super-secret-key-12345"\n'
        'DATABASE_URL = "postgresql://user:pass@localhost/db"\n'
    )

    # Package manifest
    (tmp_path / "requirements.txt").write_text(
        'flask==2.3.0\n'
        'sqlalchemy==2.0.0\n'
        'requests==2.31.0\n'
    )

    return tmp_path
