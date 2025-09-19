# app_vulns.py
# Educational demo: vulnerable vs safe patterns
# RUN ONLY IN ISOLATED LAB (VM). DO NOT DEPLOY OR EXPOSE PUBLICLY.

from flask import Flask, request, jsonify, abort, make_response, render_template
import sqlite3
import subprocess
from urllib.parse import urlparse
import socket
import requests
import ipaddress
from secrets import token_urlsafe
import html
import re

app = Flask(__name__)

# ----------- Simple SQLite setup (for demo) -----------
DB = "lab_test.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, author TEXT, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    # insert sample user (idempotent)
    c.execute("INSERT OR IGNORE INTO users(id,username,password) VALUES (1,'alice','secret')")
    c.execute("INSERT OR IGNORE INTO users(id,username,password) VALUES (2,'admin','secret')")
    c.execute("INSERT OR IGNORE INTO users(id,username,password) VALUES (3,'bob','secret')")
    # insert sample comments (idempotent)
    c.execute("INSERT OR IGNORE INTO comments(id,author,content) VALUES (1,'alice','Hello everyone!')")
    c.execute("INSERT OR IGNORE INTO comments(id,author,content) VALUES (2,'bob','Nice to meet you all.')")
    conn.commit()
    conn.close()

init_db()

# -----------------------
# 1) SQL Injection
# -----------------------

# Vulnerable endpoint (demonstrates string concat -> vulnerable)
@app.route("/sql_vuln")
def sql_vuln():
    # GET /sql_vuln?username=...
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # Vulnerable: do NOT construct queries by string concatenation
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    # For safety: limit output and don't return secrets (we show id/username)
    try:
        c.execute(query)
        rows = c.fetchall()
    except Exception as e:
        rows = [("error", str(e))]
    conn.close()
    return jsonify({"query": query, "result": rows})

# Safe endpoint (parameterized query)
@app.route("/sql_safe")
def sql_safe():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # Safe: use parameters (prevents injection)
    c.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    rows = c.fetchall()
    conn.close()
    return jsonify({"result": rows})

# -----------------------
# 2) RCE (insecure subprocess use)
# -----------------------

# Vulnerable endpoint: runs shell with untrusted input (dangerous)
@app.route("/rce_vuln", methods=["POST"])
def rce_vuln():
    """
    POST JSON: {"cmd": "<something>"}
    This endpoint demonstrates insecure use of shell=True and direct insertion
    of user input into a shell command.
    DO NOT USE shell=True with untrusted input in real apps.
    """
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    if not cmd:
        return jsonify({"error": "missing cmd"}), 400

    # WARNING: vulnerable pattern below
    try:
        # We run with shell=True to illustrate the risk. In practice this may execute arbitrary commands.
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = proc.stdout
        err = proc.stderr
    except Exception as e:
        out = ""
        err = str(e)

    return jsonify({"cmd": cmd, "stdout": out[:2000], "stderr": err[:2000]})

# Safe version: validate input and use argument list (no shell)
@app.route("/rce_safe", methods=["POST"])
def rce_safe():
    """
    POST JSON: {"filename": "<filename>"}
    Safe example: only list files inside a specific directory, validate input,
    and call subprocess with a list of args (no shell=True).
    """
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    if not filename:
        return jsonify({"error": "missing filename"}), 400

    # Simple validation: disallow path separators (prevent directory traversal)
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400

    # Only allow a short whitelist of safe commands; here we use 'ls' as example.
    try:
        proc = subprocess.run(["ls", "-la", filename], capture_output=True, text=True, timeout=5)
        return jsonify({"stdout": proc.stdout[:2000], "stderr": proc.stderr[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------
# 3) SSRF (Server-Side Request Forgery)
# -----------------------

def is_private_or_local(hostname):
    """
    Resolve hostname and check if any address is private / loopback / link-local.
    Returns True if the resolved IPs are within private ranges or loopback.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                # disallow private, loopback, link-local, multicast, unspecified
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                    return True
            except Exception:
                continue
    except Exception:
        # if resolution fails, be conservative and return True -> treat as blocked
        return True
    return False

# Vulnerable SSRF: fetches any URL provided by user (dangerous)
@app.route("/fetch_vuln")
def fetch_vuln():
    """
    GET /fetch_vuln?url=https://example.com
    Demonstrates insecure behavior: no validation of URL which can lead to SSRF.
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "missing url param"}), 400

    # Directly perform request (vulnerable)
    try:
        r = requests.get(url, timeout=5)
        content_excerpt = r.text[:2000]
        return jsonify({"url": url, "status_code": r.status_code, "content_snippet": content_excerpt})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Safer SSRF handling: whitelist + host resolution checks
ALLOWED_HOSTS = {"example.com", "httpbin.org"}  # for demo; adapt to real whitelist

@app.route("/fetch_safe")
def fetch_safe():
    """
    GET /fetch_safe?url=https://example.com/path
    Safer approach:
      - parse URL
      - allow only specific hostnames (whitelist)
      - resolve and ensure host isn't private/loopback
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "missing url param"}), 400

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "invalid url"}), 400

    # whitelist check
    if hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "hostname not allowed"}), 403

    # resolve check to avoid private IPs
    if is_private_or_local(hostname):
        return jsonify({"error": "resolved host is private or not allowed"}), 403

    try:
        r = requests.get(url, timeout=5)
        return jsonify({"url": url, "status_code": r.status_code, "content_snippet": r.text[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------
# 4) XSS (Cross-Site Scripting)
# -----------------------

# Vulnerable endpoint: XSS refletido (reflected XSS)
@app.route("/xss_vuln")
def xss_vuln():
    """
    GET /xss_vuln?name=<value>
    Demonstrates reflected XSS vulnerability: user input is directly embedded
    in HTML response without proper escaping.
    """
    name = request.args.get("name", "Guest")
    # Vulnerable: directly embedding user input in HTML without escaping
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>XSS Demo</title></head>
    <body>
        <h1>Hello, {name}!</h1>
        <p>Welcome to our vulnerable demo page.</p>
        <p>Try: <code>?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    </body>
    </html>
    """
    return make_response(html_response, 200, {'Content-Type': 'text/html'})

# Safe endpoint: XSS refletido com escape
@app.route("/xss_safe")
def xss_safe():
    """
    GET /xss_safe?name=<value>
    Safe version: properly escapes HTML entities to prevent XSS.
    """
    name = request.args.get("name", "Guest")
    # Safe: escape HTML entities
    escaped_name = html.escape(name)
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>XSS Demo - Safe</title></head>
    <body>
        <h1>Hello, {escaped_name}!</h1>
        <p>Welcome to our safe demo page.</p>
        <p>Input is properly escaped to prevent XSS.</p>
    </body>
    </html>
    """
    return make_response(html_response, 200, {'Content-Type': 'text/html'})

# Vulnerable endpoint: XSS armazenado (stored XSS)
@app.route("/comments_vuln", methods=["GET", "POST"])
def comments_vuln():
    """
    GET /comments_vuln - displays comments
    POST /comments_vuln - adds new comment (vulnerable to stored XSS)
    """
    if request.method == "POST":
        author = request.form.get("author", "")
        content = request.form.get("content", "")
        
        if author and content:
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            # Vulnerable: storing user input without validation/escaping
            c.execute("INSERT INTO comments(author, content) VALUES (?, ?)", (author, content))
            conn.commit()
            conn.close()
    
    # Display comments (vulnerable: no escaping)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT author, content, created_at FROM comments ORDER BY id DESC LIMIT 10")
    comments = c.fetchall()
    conn.close()
    
    comments_html = ""
    for author, content, created_at in comments:
        # Vulnerable: directly embedding database content in HTML
        comments_html += f"""
        <div class="comment">
            <strong>{author}</strong> <small>({created_at})</small><br>
            {content}
        </div><hr>
        """
    
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Comments - Vulnerable</title></head>
    <body>
        <h1>Comments (Vulnerable to Stored XSS)</h1>
        
        <form method="POST">
            <p>Author: <input type="text" name="author" required></p>
            <p>Comment: <textarea name="content" required></textarea></p>
            <p><input type="submit" value="Post Comment"></p>
        </form>
        
        <h2>Recent Comments:</h2>
        {comments_html}
        
        <p><strong>Warning:</strong> This page is vulnerable to stored XSS!</p>
    </body>
    </html>
    """
    return make_response(html_response, 200, {'Content-Type': 'text/html'})

# Safe endpoint: XSS armazenado com escape
@app.route("/comments_safe", methods=["GET", "POST"])
def comments_safe():
    """
    GET /comments_safe - displays comments safely
    POST /comments_safe - adds new comment (safe from stored XSS)
    """
    if request.method == "POST":
        author = request.form.get("author", "")
        content = request.form.get("content", "")
        
        if author and content:
            # Basic validation: remove/reject dangerous characters
            author = re.sub(r'[<>"\']', '', author)[:50]  # Remove dangerous chars, limit length
            content = re.sub(r'[<>"\']', '', content)[:500]  # Remove dangerous chars, limit length
            
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("INSERT INTO comments(author, content) VALUES (?, ?)", (author, content))
            conn.commit()
            conn.close()
    
    # Display comments safely
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT author, content, created_at FROM comments ORDER BY id DESC LIMIT 10")
    comments = c.fetchall()
    conn.close()
    
    comments_html = ""
    for author, content, created_at in comments:
        # Safe: escape HTML entities
        safe_author = html.escape(author)
        safe_content = html.escape(content)
        comments_html += f"""
        <div class="comment">
            <strong>{safe_author}</strong> <small>({created_at})</small><br>
            {safe_content}
        </div><hr>
        """
    
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Comments - Safe</title></head>
    <body>
        <h1>Comments (Safe from Stored XSS)</h1>
        
        <form method="POST">
            <p>Author: <input type="text" name="author" required maxlength="50"></p>
            <p>Comment: <textarea name="content" required maxlength="500"></textarea></p>
            <p><input type="submit" value="Post Comment"></p>
        </form>
        
        <h2>Recent Comments:</h2>
        {comments_html}
        
        <p><strong>Safe:</strong> Input is validated and escaped!</p>
    </body>
    </html>
    """
    return make_response(html_response, 200, {'Content-Type': 'text/html'})

# -----------------------
# Helper: index and safety note
# -----------------------
@app.route("/")
def index():
    """
    Main page with beautiful HTML interface showing all available endpoints
    """
    return render_template('index.html')

if __name__ == "__main__":
    # Simple runner for local testing (not for production)
    app.run(host="127.0.0.1", port=5000, debug=True)