import asyncio
from aiohttp import web, WSMsgType
import oqs
import sqlite3
import secrets
import logging
import smtplib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64
from datetime import datetime, timedelta
from multiprocessing import Process
import time
import shutil

# Logging setup
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables for tracking metrics
active_connections = 0  # Tracks active WebSocket connections
error_count = 0         # Tracks errors encountered
ADMIN_EMAIL = "admin@example.com"  # Email of the administrator
EMAIL_HOST = "smtp.example.com"
EMAIL_PORT = 587
EMAIL_USER = "your_email@example.com"
EMAIL_PASSWORD = "your_password"

# AES Encryption Utilities
def generate_aes_key():
    """Generate a 256-bit AES encryption key."""
    return os.urandom(32)

AES_KEY = generate_aes_key()

def encrypt_token(token, key=AES_KEY):
    """Encrypts a given token using AES-CBC with PKCS7 padding."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(token.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_token(encrypted_token, key=AES_KEY):
    """Decrypts an AES-encrypted token."""
    data = base64.b64decode(encrypted_token)
    iv, encrypted = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return (unpadder.update(decrypted) + unpadder.finalize()).decode()

# Database Initialization
def create_database():
    """Create the database and tokens table if they don't exist."""
    conn = sqlite3.connect('secure.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY,
            token TEXT UNIQUE,
            expiry DATETIME
        )
    ''')
    conn.commit()
    conn.close()

create_database()

# Token Management
def generate_token():
    """Generate a new unique token."""
    return secrets.token_hex(32)

def store_token(token, expiry_minutes=60):
    """Store a token in the database with an expiry time."""
    encrypted_token = encrypt_token(token)
    expiry = datetime.now() + timedelta(minutes=expiry_minutes)
    conn = sqlite3.connect('secure.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tokens (token, expiry) VALUES (?, ?)', (encrypted_token, expiry))
    conn.commit()
    conn.close()

def is_token_valid(token):
    """Check if a token is valid by comparing it with stored encrypted tokens."""
    encrypted_token = encrypt_token(token)
    conn = sqlite3.connect('secure.db')
    cursor = conn.cursor()
    cursor.execute('SELECT expiry FROM tokens WHERE token = ?', (encrypted_token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        expiry = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
        return datetime.now() < expiry
    return False

# Post-quantum Cryptography Handshake
def post_quantum_handshake():
    """Generate a Kyber512 public key for secure key exchange."""
    with oqs.KeyEncapsulation("Kyber512") as server:
        public_key = server.generate_keypair()
        logging.info("Server public key generated for post-quantum handshake.")
        return public_key, server

# Backup Process
def backup_database():
    """Create periodic backups of the database."""
    while True:
        backup_file = f"secure_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"
        try:
            shutil.copy('secure.db', backup_file)
            logging.info(f"Backup created: {backup_file}")
        except Exception as e:
            global error_count
            error_count += 1
            logging.error(f"Backup failed: {e}")
            send_email_notification("Backup failure", f"Error during backup: {e}")
        finally:
            time.sleep(300)  # Backup every 5 minutes

# WebSocket Support
async def websocket_handler(request):
    """Handle WebSocket connections and messages."""
    global active_connections
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    active_connections += 1
    logging.info(f"WebSocket connection opened. Active connections: {active_connections}")

    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            if msg.data == 'close':
                await ws.close()
            else:
                response = f"Echo: {msg.data}"
                await ws.send_str(response)
        elif msg.type == WSMsgType.ERROR:
            global error_count
            error_count += 1
            logging.error(f"WebSocket connection closed with exception: {ws.exception()}")

    active_connections -= 1
    logging.info(f"WebSocket connection closed. Active connections: {active_connections}")
    return ws

# Rate Limiting Middleware
RATE_LIMIT = 10  # Requests per minute
clients = {}

async def rate_limiter_middleware(app, handler):
    """Middleware for enforcing rate limits."""
    async def middleware_handler(request):
        ip = request.remote
        now = datetime.now()
        if ip not in clients:
            clients[ip] = []
        clients[ip] = [t for t in clients[ip] if t > now - timedelta(minutes=1)]
        if len(clients[ip]) >= RATE_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {ip}")
            send_email_notification("Rate limit exceeded", f"IP {ip} exceeded rate limit.")
            return web.Response(status=429, text="Too many requests, slow down.")
        clients[ip].append(now)
        return await handler(request)
    return middleware_handler

# CSRF Protection
csrf_tokens = {}

def generate_csrf_token(session_id):
    """Generate a CSRF token for a session."""
    token = secrets.token_hex(16)
    csrf_tokens[session_id] = token
    return token

def validate_csrf_token(session_id, token):
    """Validate a CSRF token for a session."""
    return csrf_tokens.get(session_id) == token

# Email Notification Function
def send_email_notification(subject, message):
    """Send email notifications to the administrator."""
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            email_message = f"Subject: {subject}\n\n{message}"
            server.sendmail(EMAIL_USER, ADMIN_EMAIL, email_message)
        logging.info(f"Notification sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Web server setup
async def handle_request(request):
    """Handle HTTP requests with CSRF validation and token management."""
    global error_count
    start_time = time.time()
    try:
        data = await request.json()
        session_id = request.cookies.get("SESSION_ID")
        csrf_token = data.get('csrf_token')

        if not session_id or not validate_csrf_token(session_id, csrf_token):
            return web.Response(status=403, text="CSRF token is invalid.")

        action = data.get('action', '')
        if action == 'generate_token':
            token = generate_token()
            store_token(token)
            return web.Response(text=f"Token generated: {token}")
        elif action == 'validate_token':
            token = data.get('token', '')
            if is_token_valid(token):
                return web.Response(text="Token is valid.")
            else:
                return web.Response(status=403, text="Token is invalid.")
        else:
            return web.Response(status=400, text="Invalid action.")
    except Exception as e:
        error_count += 1
        logging.error(f"Error processing request: {e}")
        send_email_notification("Request processing error", f"Error processing request: {e}")
        return web.Response(status=500, text="Internal server error.")
    finally:
        end_time = time.time()
        logging.info(f"Request processed in {end_time - start_time:.2f}s.")

async def start_server():
    """Start the web server with middleware and route setup."""
    app = web.Application(middlewares=[rate_limiter_middleware])
    app.router.add_post('/', handle_request)
    app.router.add_get('/ws', websocket_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()
    logging.info("Server started on localhost:8080")

if __name__ == "__main__":
    backup_process = Process(target=backup_database)
    backup_process.start()
    asyncio.run(start_server())




