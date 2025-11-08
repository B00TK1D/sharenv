#!/usr/bin/env python3
"""
Shared environment variables server with key rotation support.
Serves environment variables from the ./vars directory as shell export commands.
"""

import os
import time
import hashlib
import logging
import secrets
import random
from pathlib import Path
from threading import Lock
from flask import Flask, Response, request, abort
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

# Configuration
VARS_DIR = Path('./vars')
ALIASES_FILE = Path('./aliases')
CACHE_TTL = 1  # Cache TTL in seconds for hot-reload
ROTATION_INTERVAL = 60  # Rotate through values every N seconds

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sharenv.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Get or generate secret token
SECRET_TOKEN = os.environ.get('SHARENV_TOKEN')
if not SECRET_TOKEN:
    # Generate a random 16-character hex string
    SECRET_TOKEN = secrets.token_hex(8)  # 8 bytes = 16 hex characters
    logger.warning(f"SHARENV_TOKEN not set, generated random token: {SECRET_TOKEN}")
else:
    logger.info(f"Using SHARENV_TOKEN from environment")
logger.info(f"Secret token: {SECRET_TOKEN}")

# In-memory cache
_values_cache = {}  # Cache the values list from files
_cache_lock = Lock()
_cache_timestamps = {}
_file_hashes = {}
_aliases_cache = None
_aliases_hash = None


class VarsFileHandler(FileSystemEventHandler):
    """Handle file system events for hot-reloading."""

    def on_modified(self, event):
        if not event.is_directory:
            event_path = Path(event.src_path).resolve()
            vars_dir_path = VARS_DIR.resolve()
            aliases_file_path = ALIASES_FILE.resolve()

            if str(event_path).startswith(str(vars_dir_path)):
                # Invalidate cache for this file
                var_name = event_path.stem
                with _cache_lock:
                    if var_name in _values_cache:
                        del _values_cache[var_name]
                    if var_name in _file_hashes:
                        del _file_hashes[var_name]
            elif event_path == aliases_file_path:
                # Invalidate aliases cache
                with _cache_lock:
                    global _aliases_cache, _aliases_hash
                    _aliases_cache = None
                    _aliases_hash = None


def get_file_hash(filepath):
    """Get MD5 hash of file contents."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None


def read_var_file(var_name):
    """Read environment variable file and return all values."""
    filepath = VARS_DIR / var_name
    if not filepath.exists():
        return None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        return lines if lines else None
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return None


def get_var_value(var_name):
    """Get the current value for a variable, with random rotation support."""
    current_time = time.time()

    with _cache_lock:
        filepath = VARS_DIR / var_name
        current_hash = get_file_hash(filepath)
        
        # Check if we have cached values and if file hasn't changed
        if var_name in _values_cache and var_name in _file_hashes:
            cache_time = _cache_timestamps.get(var_name, 0)
            if (_file_hashes[var_name] == current_hash and 
                current_time - cache_time < CACHE_TTL):
                # Use cached values list
                values = _values_cache[var_name]
            else:
                # File changed or cache expired, read fresh
                values = read_var_file(var_name)
                if values is None:
                    return None
                _values_cache[var_name] = values
                _file_hashes[var_name] = current_hash
                _cache_timestamps[var_name] = current_time
        else:
            # No cache, read file
            values = read_var_file(var_name)
            if values is None:
                return None
            _values_cache[var_name] = values
            _file_hashes[var_name] = current_hash
            _cache_timestamps[var_name] = current_time

        # Randomly select from values if multiple exist
        if len(values) > 1:
            selected_value = random.choice(values)
        else:
            selected_value = values[0]

        return selected_value


def load_all_vars():
    """Load all environment variables from the vars directory."""
    if not VARS_DIR.exists():
        VARS_DIR.mkdir(parents=True, exist_ok=True)
        return {}

    vars_dict = {}
    for filepath in VARS_DIR.iterdir():
        if filepath.is_file() and not filepath.name.startswith('.'):
            var_name = filepath.name
            value = get_var_value(var_name)
            if value is not None:
                vars_dict[var_name] = value

    return vars_dict


def load_aliases():
    """Load aliases from the aliases file."""
    global _aliases_cache, _aliases_hash

    if not ALIASES_FILE.exists():
        return []

    with _cache_lock:
        # Check if cache is valid
        current_hash = get_file_hash(ALIASES_FILE)
        if _aliases_cache is not None and _aliases_hash == current_hash:
            return _aliases_cache

        # Read aliases file
        try:
            with open(ALIASES_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]

            # Process each line - format as proper alias command
            aliases = []
            for line in lines:
                if line.startswith('alias '):
                    # Already formatted as alias command
                    aliases.append(line)
                else:
                    # Parse the line and format as alias command
                    # Handle formats like: name='value', name="value", or name=value
                    if '=' in line:
                        parts = line.split('=', 1)
                        alias_name = parts[0].strip()
                        alias_value = parts[1].strip()
                        
                        # If value is already quoted, use as-is; otherwise quote it
                        if (alias_value.startswith("'") and alias_value.endswith("'")) or \
                           (alias_value.startswith('"') and alias_value.endswith('"')):
                            # Already quoted, use as-is
                            aliases.append(f'alias {alias_name}={alias_value}')
                        else:
                            # Not quoted, add single quotes
                            aliases.append(f"alias {alias_name}='{alias_value}'")
                    else:
                        # No equals sign, treat entire line as alias name (no value)
                        aliases.append(f'alias {line.strip()}')

            # Update cache
            _aliases_cache = aliases
            _aliases_hash = current_hash

            return aliases
        except Exception as e:
            logger.error(f"Error reading {ALIASES_FILE}: {e}")
            return []


def get_client_ip():
    """Get the client's IP address from the request."""
    # Check for X-Forwarded-For header (for proxies/load balancers)
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first one
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # Check for X-Real-IP header
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    # Fall back to remote_addr
    else:
        return request.remote_addr or 'unknown'


def validate_token(token):
    """Validate that the provided token matches the secret token."""
    if token != SECRET_TOKEN:
        logger.warning(f"Invalid token attempt from {get_client_ip()}")
        return False
    return True


@app.route('/', methods=['GET'])
def install_instructions():
    """
    Return installation instructions for the sharenv client.
    """
    # Get the base URL for the endpoint
    base_url = request.url_root.rstrip('/')

    # Use a placeholder token in the instructions (don't leak the secret)
    example_endpoint = f'{base_url}/your-secret-token'

    # Check if user agent is curl - return simple text instructions
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'curl' in user_agent:
        simple_instructions = f"""sharenv - Quick Install:
export SHARENV_ENDPOINT="{example_endpoint}"
eval $(curl -s $SHARENV_ENDPOINT)
"""
        return Response(simple_instructions, mimetype='text/plain')

    instructions = f"""<!DOCTYPE html>
<html>
<head>
    <title>sharenv - Installation Instructions</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
        }}
        pre {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #3498db;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .info {{
            background-color: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 20px 0;
        }}
        .step {{
            background-color: #f8f9fa;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }}
    </style>
</head>
<body>
    <h1>🚀 sharenv - Installation Instructions</h1>

    <p>Welcome to <strong>sharenv</strong>! This service allows you to share environment variables and aliases across multiple machines.</p>

    <div class="info">
        <strong>📋 Quick Install:</strong> Add the following to your shell profile (<code>~/.bashrc</code>, <code>~/.zshrc</code>, etc.)
    </div>

    <div class="step">
        <h2>Step 1: Set your endpoint</h2>
        <p>Add this line to your shell profile (replace <code>your-secret-token</code> with your actual token):</p>
        <pre>export SHARENV_ENDPOINT="{example_endpoint}"</pre>
    </div>

    <div class="step">
        <h2>Step 2: Load environment variables</h2>
        <p>Add this line to your shell profile:</p>
        <pre>eval $(curl -s $SHARENV_ENDPOINT)</pre>
    </div>

    <div class="step">
        <h2>Step 3: Apply changes</h2>
        <p>Source your profile or restart your terminal:</p>
        <pre>source ~/.bashrc  # or ~/.zshrc</pre>
        <p>Or simply open a new terminal window.</p>
    </div>

    <h2>📝 Complete Example</h2>
    <p>For <strong>bash</strong> (<code>~/.bashrc</code>):</p>
    <pre>export SHARENV_ENDPOINT="{example_endpoint}"
eval $(curl -s $SHARENV_ENDPOINT)</pre>

    <p>For <strong>zsh</strong> (<code>~/.zshrc</code>):</p>
    <pre>export SHARENV_ENDPOINT="{example_endpoint}"
eval $(curl -s $SHARENV_ENDPOINT)</pre>

    <div class="warning">
        <strong>⚠️ Security Note:</strong> Make sure to use a secure token in your endpoint URL. The token acts as authentication for accessing your environment variables.
    </div>

    <h2>🔧 How It Works</h2>
    <ul>
        <li>The server serves environment variables and aliases as shell commands</li>
        <li>Changes to variables and aliases are hot-reloaded automatically</li>
        <li>Multiple values per variable are rotated automatically</li>
    </ul>

    <h2>📚 More Information</h2>
    <p>For more details, see the <a href="https://github.com/your-repo/sharenv">project repository</a>.</p>

    <hr>
    <p style="text-align: center; color: #7f8c8d; font-size: 0.9em;">
        sharenv - Shared environment variables with key rotation support
    </p>
</body>
</html>"""

    return Response(instructions, mimetype='text/html')


@app.route('/<path:token>', methods=['GET'])
def get_env_vars(token):
    """
    Serve environment variables and aliases as shell commands.
    The token in the path can be used for authentication/identification.
    """
    # Validate token
    if not validate_token(token):
        # Return a bash echo statement warning about the wrong key
        warning_message = 'echo "Warning: Invalid sharenv key. Please check your SHARENV_ENDPOINT configuration."'
        return Response(warning_message, mimetype='text/plain')
    
    vars_dict = load_all_vars()
    aliases = load_aliases()

    # Generate shell export commands
    export_commands = []
    for var_name, value in sorted(vars_dict.items()):
        # Escape special characters in the value
        escaped_value = value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
        export_commands.append(f'export {var_name}="{escaped_value}"')

    # Aliases should already be in the correct format from load_aliases()
    # They're formatted as "alias name='value'" commands
    # Ensure aliases are set in the current shell (not a subshell)
    # Combine exports and aliases - aliases will be executed as alias commands, not env vars
    all_commands = export_commands + aliases
    response_text = '\n'.join(all_commands)
    
    # Note: When using eval $(curl -s $SHARENV_ENDPOINT), aliases should work correctly
    # because eval executes commands in the current shell context, not a subshell

    return Response(
        response_text,
        mimetype='text/plain',
        headers={
            'Content-Type': 'text/plain; charset=utf-8'
        }
    )


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return {'status': 'ok', 'vars_dir': str(VARS_DIR)}


def start_file_watcher():
    """Start watching the vars directory and aliases file for changes."""
    if not VARS_DIR.exists():
        VARS_DIR.mkdir(parents=True, exist_ok=True)

    event_handler = VarsFileHandler()
    observer = Observer()
    observer.schedule(event_handler, str(VARS_DIR), recursive=False)

    # Also watch the parent directory for the aliases file
    parent_dir = VARS_DIR.parent
    observer.schedule(event_handler, str(parent_dir), recursive=False)

    observer.start()
    return observer


if __name__ == '__main__':
    # Ensure vars directory exists
    if not VARS_DIR.exists():
        VARS_DIR.mkdir(parents=True, exist_ok=True)

    # Start file watcher for hot-reloading
    observer = start_file_watcher()

    try:
        # Get port from environment or default to 5000
        port = int(os.environ.get('PORT', 5000))
        host = os.environ.get('HOST', '0.0.0.0')

        logger.info(f"Starting sharenv server on {host}:{port}")
        logger.info(f"Vars directory: {VARS_DIR.absolute()}")
        logger.info(f"Aliases file: {ALIASES_FILE.absolute()}")

        app.run(host=host, port=port, debug=False)
    finally:
        observer.stop()
        observer.join()
