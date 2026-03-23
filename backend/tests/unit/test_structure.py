"""Tests for structural code analysis."""

from app.analysis.structure import extract_structure


def test_extract_python_functions():
    code = '''
import os
from flask import Flask, request

app = Flask(__name__)

def helper():
    pass

class AuthController:
    def login(self, username, password):
        pass

    def logout(self):
        pass

@app.route("/api/data")
def get_data():
    user_id = request.args.get("id")
    return {"id": user_id}
'''
    result = extract_structure(code, "python")

    func_names = [s.name for s in result.symbols if s.kind == "function"]
    assert "helper" in func_names
    assert "get_data" in func_names

    class_names = [s.name for s in result.symbols if s.kind == "class"]
    assert "AuthController" in class_names

    method_names = [s.name for s in result.symbols if s.kind == "method"]
    assert "login" in method_names
    assert "logout" in method_names

    assert "os" in result.imports or any("os" in imp for imp in result.imports)
    assert len(result.routes) >= 1
    assert result.routes[0]["path"] == "/api/data"


def test_extract_javascript_functions():
    code = '''
import express from "express";
const jwt = require("jsonwebtoken");

function validateToken(token) {
    return jwt.verify(token, secret);
}

const handleRequest = async (req, res) => {
    const data = req.body;
    res.json(data);
};

class UserService {
    async createUser(data) {
        return db.insert(data);
    }
}

app.post("/api/users", handleRequest);
'''
    result = extract_structure(code, "javascript")

    func_names = [s.name for s in result.symbols if s.kind == "function"]
    assert "validateToken" in func_names
    assert "handleRequest" in func_names

    class_names = [s.name for s in result.symbols if s.kind == "class"]
    assert "UserService" in class_names

    assert any("express" in imp for imp in result.imports)
    assert any("jsonwebtoken" in imp for imp in result.imports)


def test_security_tagging():
    code = '''
def authenticate_user(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchone()
'''
    result = extract_structure(code, "python")

    func = next(s for s in result.symbols if s.name == "authenticate_user")
    assert func.tags.get("auth") or func.tags.get("crypto") or func.tags.get("db_access")
