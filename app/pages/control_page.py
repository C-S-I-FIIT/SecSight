import streamlit as st
import subprocess
import os
import signal
import threading
import time
from pathlib import Path
import sys
import json
from typing import Dict, Optional, List, Tuple
import re
from datetime import datetime, timedelta
import dotenv
from dotenv import load_dotenv, set_key, find_dotenv

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import the VaultClient
from app.clients.vault_client import VaultClient

# Path to the default rules path file
DEFAULT_RULES_PATH_FILE = ".default-rule-path"
DEFAULT_RULES_PATH = "./rules"

# Environment variable configuration
ENV_FILE = find_dotenv() or ".env"
ENV_VARS = {
    "VAULT_ADDR": {"default": "https://vault.example.com", "description": "Vault server address"},
    "VAULT_TOKEN": {"default": "", "description": "Vault authentication token", "is_secret": True},
    "ATTACK_NAVIGATOR_URL": {"default": "https://mitre-attack.github.io/attack-navigator/", "description": "MITRE ATT&CK Navigator URL"},
    "SIGMA_RULES_PATH": {"default": "./rules", "description": "Path to Sigma rules directory"}
}

# ANSI color codes regex pattern for terminal colors
ANSI_COLOR_PATTERN = re.compile(r'\033\[[0-9;]+m')

# ANSI to HTML color mapping
# Mapping based on standard ANSI color codes
ANSI_COLOR_MAP = {
    '30': 'color: black;',
    '31': 'color: red;',
    '32': 'color: green;',
    '33': 'color: yellow;',
    '34': 'color: blue;',
    '35': 'color: magenta;',
    '36': 'color: cyan;',
    '37': 'color: lightgray;',
    '90': 'color: darkgray;',
    '91': 'color: lightred;',
    '92': 'color: lightgreen;',
    '93': 'color: lightyellow;',
    '94': 'color: lightblue;',
    '95': 'color: lightmagenta;',
    '96': 'color: lightcyan;',
    '97': 'color: white;',
    '40': 'background-color: black;',
    '41': 'background-color: red;',
    '42': 'background-color: green;',
    '43': 'background-color: yellow;',
    '44': 'background-color: blue;',
    '45': 'background-color: magenta;',
    '46': 'background-color: cyan;',
    '47': 'background-color: lightgray;',
    '100': 'background-color: darkgray;',
    '101': 'background-color: lightred;',
    '102': 'background-color: lightgreen;',
    '103': 'background-color: lightyellow;',
    '104': 'background-color: lightblue;',
    '105': 'background-color: lightmagenta;',
    '106': 'background-color: lightcyan;',
    '107': 'background-color: white;',
    '1': 'font-weight: bold;',
    '2': 'opacity: 0.8;',
    '3': 'font-style: italic;',
    '4': 'text-decoration: underline;',
    '0': ''  # Reset
}

def load_default_rules_path() -> str:
    """Load the default rules path from the file, or return empty string if not found."""
    try:
        if os.path.exists(DEFAULT_RULES_PATH_FILE):
            with open(DEFAULT_RULES_PATH_FILE, "r") as f:
                path = f.read().strip()
                return path if path else ""
        return ""
    except Exception:
        return ""

def save_default_rules_path(path: str) -> None:
    """Save the default rules path to a file."""
    try:
        with open(DEFAULT_RULES_PATH_FILE, "w") as f:
            f.write(path)
    except Exception as e:
        st.error(f"Failed to save default path: {str(e)}")

def load_env_vars() -> Dict[str, str]:
    """Load environment variables from .env file."""
    # Ensure the .env file exists
    if not os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'w') as f:
            pass
    
    # Load environment variables
    load_dotenv(ENV_FILE, override=True)
    
    # Get environment variables
    env_vars = {}
    for key in ENV_VARS.keys():
        env_vars[key] = os.environ.get(key, ENV_VARS[key]["default"])
    
    return env_vars

def save_env_vars(env_vars: Dict[str, str]) -> None:
    """Save environment variables to .env file."""
    for key, value in env_vars.items():
        set_key(ENV_FILE, key, value)

def ansi_to_html(text: str) -> str:
    """Convert ANSI escape sequences to HTML spans with inline CSS styling."""
    if not text:
        return ""
    
    # Split by ANSI escape sequences
    fragments = []
    cursor = 0
    spans_open = False
    current_style = []
    
    # Find all ANSI escape sequences
    for match in re.finditer(r'\033\[([0-9;]+)m', text):
        # Add text before the sequence
        if match.start() > cursor:
            if spans_open:
                fragments.append(f'<span style="{";".join(current_style)}">')
                spans_open = True
            fragments.append(text[cursor:match.start()])
            if spans_open:
                fragments.append('</span>')
        
        # Process the ANSI codes
        codes = match.group(1).split(';')
        
        # Reset styles if 0 is present
        if '0' in codes:
            current_style = []
        
        # Add styles for each code
        for code in codes:
            if code in ANSI_COLOR_MAP:
                if ANSI_COLOR_MAP[code] and ANSI_COLOR_MAP[code] not in current_style:
                    current_style.append(ANSI_COLOR_MAP[code])
        
        cursor = match.end()
    
    # Add remaining text
    if cursor < len(text):
        if current_style:
            fragments.append(f'<span style="{";".join(current_style)}">')
            fragments.append(text[cursor:])
            fragments.append('</span>')
        else:
            fragments.append(text[cursor:])
    
    return ''.join(fragments)

class ScriptRunner:
    """Class to handle running collector.py with arguments and capturing output."""
    
    def __init__(self):
        self.process = None
        self.output_lines = []  # newest logs at index 0, oldest at the end
        self.running = False
        self.lock = threading.Lock()
    
    def run_collector(self, args: List[str]) -> None:
        """Run collector.py with the given arguments and capture output."""
        collector_path = str(Path(__file__).parent.parent.parent / "collector.py")
        
        command = [sys.executable, collector_path] + args
        
        try:
            # Set up environment variables for the subprocess
            env = os.environ.copy()
            
            # Use environment variables from settings
            env_vars = load_env_vars()
            for key, value in env_vars.items():
                if value:  # Only set if there's a value
                    env[key] = value
            
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env
            )
            
            self.running = True
            
            # Ensure process and stdout are not None before reading
            if self.process and self.process.stdout:
                while self.running and self.process.poll() is None:
                    line = self.process.stdout.readline()
                    if line:
                        with self.lock:
                            # Prepend new logs at the start
                            self.output_lines.insert(0, line.rstrip())
                    else:
                        time.sleep(0.1)
            
            # Read any remaining output
            if self.process:
                remaining_output, _ = self.process.communicate()
                if remaining_output:
                    with self.lock:
                        # Prepend new logs at the start
                        for line in reversed(remaining_output.splitlines()):
                            self.output_lines.insert(0, line.rstrip())
        
        except Exception as e:
            with self.lock:
                # Prepend error message at the start
                self.output_lines.insert(0, f"Error running collector script: {str(e)}")
        
        finally:
            self.running = False
    
    def stop(self) -> None:
        """Stop the running process if it exists."""
        if self.process and self.running:
            try:
                if sys.platform == "win32":
                    self.process.terminate()
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception as e:
                with self.lock:
                    self.output_lines.append(f"Error stopping process: {str(e)}")
            
            self.running = False
    
    def clear_output(self) -> None:
        """Clear all output lines."""
        with self.lock:
            self.output_lines = []
    
    def get_output(self) -> List[str]:
        """Get the current output lines with thread safety."""
        with self.lock:
            return self.output_lines.copy()

def show_control_page():
    st.title("Collector Control Panel")
    
    # Initialize session state for the script runner
    if "script_runner" not in st.session_state or not hasattr(st.session_state.script_runner, "clear_output"):
        st.session_state.script_runner = ScriptRunner()
    
    # Load default sigma rules path
    if "sigma_rules_path" not in st.session_state:
        st.session_state.sigma_rules_path = load_default_rules_path()
    
    # Load environment variables
    if "env_vars" not in st.session_state:
        st.session_state.env_vars = load_env_vars()
    
    # Initialize state for password visibility
    if "password_visible" not in st.session_state:
        st.session_state.password_visible = {}
        for key in ENV_VARS.keys():
            if ENV_VARS.get(key, {}).get("is_secret", False):
                st.session_state.password_visible[key] = False
    
    # Create tabs for different sections
    collector_tab, env_tab = st.tabs(["Collector Options", "Environment Settings"])
    
    with collector_tab:
        # Information about the collector script
        st.info("""
        This panel allows you to run the data collector script with various options:
        
        - **MITRE**: Collect MITRE ATT&CK framework data (optionally specify version or 'force')
        - **Netbox**: Get hosts from Netbox and update database
        - **Netbox Windows Only**: Only collect Windows hosts from Netbox
        - **Winlogbeat**: Process Winlogbeat configurations (requires Netbox)
        - **Sigma**: Process Sigma rules and calculate coverage (requires Sigma Rules Path)
        - **TheHive**: Run TheHive collector with sync_all
        - **All**: Run all collectors (requires Sigma Rules Path)
        - **Verbose**: Increase logging verbosity (can be selected multiple times)
        - **Date Range**: Specify data collection period (Days back, From date, To date)
        """)
        
        # Define collector options
        col1, col2 = st.columns(2)
        
        with col1:
            mitre_enabled = st.checkbox("MITRE", value=False, key="mitre")
            mitre_version = st.text_input("MITRE Version (optional, or 'force')", key="mitre_version")
            
            netbox_enabled = st.checkbox("Netbox", value=False, key="netbox")
            netbox_windows_only = st.checkbox("Netbox Windows Only", value=False, key="netbox_windows_only")
            
            winlogbeat_enabled = st.checkbox("Winlogbeat", value=False, key="winlogbeat")
        
        with col2:
            sigma_enabled = st.checkbox("Sigma", value=False, key="sigma")
            
            # Use the Sigma rules path from environment variables if available
            sigma_rules_path = st.text_input(
                "Sigma Rules Path", 
                value=st.session_state.env_vars.get("SIGMA_RULES_PATH", st.session_state.sigma_rules_path),
                key="sigma_rules_path_input"
            )
            
            thehive_enabled = st.checkbox("TheHive", value=False, key="thehive")
            all_enabled = st.checkbox("All", value=False, key="all")
            
            verbose_level = st.radio(
                "Verbose Level",
                options=[0, 1, 2],
                horizontal=True,
                help="0: Normal, 1: Verbose, 2: Very Verbose"
            )
        
        # Date range options
        st.subheader("Date Range Options")
        
        date_option = st.radio(
            "Select date range option:",
            options=["No date filter", "Days back", "Date range"],
            horizontal=True
        )
        
        days_back = None
        from_date = None
        to_date = None
        
        if date_option == "Days back":
            days_back = st.number_input("Number of days back:", min_value=1, value=7)
            st.info(f"Will collect data from {(datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')} to today")
        
        elif date_option == "Date range":
            col1, col2 = st.columns(2)
            with col1:
                # Default to 7 days ago
                default_from = datetime.now() - timedelta(days=7)
                from_date = st.date_input("From date:", value=default_from)
            with col2:
                # Default to today
                to_date = st.date_input("To date:", value=datetime.now())
            
            if from_date > to_date:
                st.error("From date must be before To date")
        
        # Default path management
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Set Default Rules Path"):
                if sigma_rules_path:
                    save_default_rules_path(sigma_rules_path)
                    st.session_state.sigma_rules_path = sigma_rules_path
                    
                    # Also update the environment variable
                    env_vars = st.session_state.env_vars.copy()
                    env_vars["SIGMA_RULES_PATH"] = sigma_rules_path
                    save_env_vars(env_vars)
                    st.session_state.env_vars = env_vars
                    
                    st.success(f"Default rules path set to: {sigma_rules_path}")
                else:
                    st.warning("Please enter a rules path first")
        
        with col2:
            if st.button("Use Default Path"):
                default_path = st.session_state.env_vars.get("SIGMA_RULES_PATH", DEFAULT_RULES_PATH)
                st.session_state.sigma_rules_path = default_path
                sigma_rules_path = default_path
                st.rerun()
        
        # Validate inputs
        validation_errors = []
        
        if (sigma_enabled or all_enabled) and not sigma_rules_path:
            validation_errors.append("Sigma Rules Path is required when Sigma or All is enabled")
        
        if winlogbeat_enabled and not netbox_enabled:
            validation_errors.append("Netbox must be enabled when Winlogbeat is enabled")
        
        if date_option == "Date range" and from_date and to_date and from_date > to_date:
            validation_errors.append("From date must be before To date")
        
        # Display validation errors
        for error in validation_errors:
            st.error(error)
        
        # Control buttons
        col1, col2 = st.columns(2)
        
        with col1:
            run_button = st.button(
                "Run Collector",
                disabled=len(validation_errors) > 0 or st.session_state.script_runner.running
            )
        
        with col2:
            stop_button = st.button(
                "Stop Collector",
                disabled=not st.session_state.script_runner.running
            )
        
        # Run the collector when the run button is clicked
        if run_button and not st.session_state.script_runner.running:
            # Build the arguments list
            args = []
            
            if mitre_enabled:
                if mitre_version:
                    args.extend(["--mitre", mitre_version])
                else:
                    args.append("--mitre")
            
            if netbox_enabled:
                args.append("--netbox")
            
            if netbox_windows_only:
                args.append("--netbox-windows-only")
            
            if winlogbeat_enabled:
                args.append("--winlogbeat")
            
            if sigma_enabled:
                args.append("--sigma")
                args.extend(["--sigma-rules-path", sigma_rules_path])
            
            if thehive_enabled:
                args.append("--thehive")
            
            if all_enabled:
                args.append("--all")
                args.extend(["--sigma-rules-path", sigma_rules_path])
            
            # Add verbose flags
            for _ in range(verbose_level):
                args.append("--verbose")
            
            # Add date range options
            if date_option == "Days back" and days_back:
                args.extend(["--days", str(days_back)])
            elif date_option == "Date range" and from_date and to_date:
                # Format dates as YYYY-MM-DD
                from_date_str = from_date.strftime("%Y-%m-%d")
                to_date_str = to_date.strftime("%Y-%m-%d")
                args.extend(["--from", from_date_str])
                args.extend(["--to", to_date_str])
            
            # Start the script in a new thread
            thread = threading.Thread(
                target=st.session_state.script_runner.run_collector,
                args=(args,),
                daemon=True
            )
            thread.start()
        
        # Handle stop button
        if stop_button and st.session_state.script_runner.running:
            st.session_state.script_runner.stop()
            st.info("Stopping collector script... This may take a moment.")
        
        # Display output
        st.subheader("Collector Output")
        
        # Add clear output button
        if st.button("Clear Output"):
            # Check if clear_output exists before calling it
            if hasattr(st.session_state.script_runner, "clear_output"):
                st.session_state.script_runner.clear_output()
                st.info("Output cleared.")
                time.sleep(0.5)
                st.rerun()
            else:
                # If method doesn't exist, recreate the script_runner object
                st.session_state.script_runner = ScriptRunner()
                st.info("Output cleared.")
                time.sleep(0.5)
                st.rerun()
        
        # Process output with ANSI color support
        output_lines = st.session_state.script_runner.get_output()
        # Note: output_lines are already ordered with newest logs first (index 0)
        
        # Convert ANSI colors to HTML
        html_lines = []
        for line in output_lines:
            html_line = ansi_to_html(line)
            html_lines.append(html_line)
        
        # Join with HTML line breaks
        html_output = '<br>'.join(html_lines)
        
        # Use a container with fixed height and scrolling for the output
        with st.container():
            st.markdown("""
            <style>
            .fixed-height-container {
                height: 400px;
                overflow-y: auto;
                border: 1px solid #e0e0e0;
                padding: 10px;
                background-color: #000000;
                font-family: monospace;
                white-space: pre-wrap;
                color: #f0f0f0;
                /* Ensure container starts scrolled to the top */
                scroll-behavior: auto;
                overflow-anchor: none;
            }
            /* Ensure newest logs (at the top) are always visible */
            .fixed-height-container:before {
                content: "";
                display: block;
                height: 0;
                float: left;
            }
            </style>
            """, unsafe_allow_html=True)
            
            # Display the output with newest logs at the top
            st.markdown(f"""
            <div class="fixed-height-container">
            {html_output}
            </div>
            """, unsafe_allow_html=True)
        
        # Auto-update the output while the script is running
        if st.session_state.script_runner.running:
            st.info("Script is running... Output will update automatically.")
            st.write(f"Auto-refreshing... {datetime.now().strftime('%H:%M:%S')}")
    
            
            # Add auto-refresh functionality that doesn't interfere with UI
            refresh_placeholder = st.empty()
            with refresh_placeholder.container():
                st.markdown("""
                <style>
                /* Hide the refresh container */
                div[data-testid="stExpander"] {
                    display: none;
                }
                </style>
                """, unsafe_allow_html=True)
                
                # This will trigger a rerun every second while the script is running
                time.sleep(1)
                st.rerun()
        
        # Add a manual refresh button for users to force refresh
        if st.button("Refresh Output"):
            st.rerun()

    
    with env_tab:
        st.header("Environment Variables")
        st.info("Configure environment variables used by the collector script. These will be saved to the .env file.")
        
        # Environment Variables Section
        env_vars = {}
        for key, config in ENV_VARS.items():
            st.subheader(f"{key}")
            st.caption(config["description"])
            
            is_secret = config.get("is_secret", False)
            
            # For secret fields, add a visibility toggle
            if is_secret:
                if st.session_state.password_visible.get(key, False):
                    env_vars[key] = st.text_input(
                        f"{key} Value",
                        value=st.session_state.env_vars.get(key, config["default"]),
                        key=f"env_{key}"
                    )
                else:
                    env_vars[key] = st.text_input(
                        f"{key} Value",
                        value=st.session_state.env_vars.get(key, config["default"]),
                        type="password",
                        key=f"env_{key}"
                    )
            else:
                env_vars[key] = st.text_input(
                    f"{key} Value",
                    value=st.session_state.env_vars.get(key, config["default"]),
                    key=f"env_{key}"
                )
        
        # Test Vault Connection
        if "VAULT_ADDR" in env_vars and "VAULT_TOKEN" in env_vars:
            if st.button("Test Vault Connection"):
                try:
                    # Create a temporary environment with the current values
                    temp_env = os.environ.copy()
                    temp_env["VAULT_ADDR"] = env_vars["VAULT_ADDR"]
                    temp_env["VAULT_TOKEN"] = env_vars["VAULT_TOKEN"]
                    
                    # Set environment variables temporarily
                    old_addr = os.environ.get("VAULT_ADDR")
                    old_token = os.environ.get("VAULT_TOKEN")
                    os.environ["VAULT_ADDR"] = env_vars["VAULT_ADDR"]
                    os.environ["VAULT_TOKEN"] = env_vars["VAULT_TOKEN"]
                    
                    try:
                        # Create the client and test connection
                        vault_client = VaultClient()
                        if vault_client.test_connection():
                            st.success("Successfully connected to Vault!")
                        else:
                            st.error("Failed to authenticate with Vault. Please check your credentials.")
                    except Exception as e:
                        st.error(f"Vault connection error: {str(e)}")
                    finally:
                        # Restore original environment variables
                        if old_addr:
                            os.environ["VAULT_ADDR"] = old_addr
                        else:
                            os.environ.pop("VAULT_ADDR", None)
                            
                        if old_token:
                            os.environ["VAULT_TOKEN"] = old_token
                        else:
                            os.environ.pop("VAULT_TOKEN", None)
                except Exception as e:
                    st.error(f"Error testing Vault connection: {str(e)}")
        
        # Apply changes to environment variables
        if st.button("Save Environment Variables"):
            save_env_vars(env_vars)
            st.session_state.env_vars = env_vars
            
            # Also update the sigma rules path in the session state
            if "SIGMA_RULES_PATH" in env_vars and env_vars["SIGMA_RULES_PATH"]:
                st.session_state.sigma_rules_path = env_vars["SIGMA_RULES_PATH"]
                save_default_rules_path(env_vars["SIGMA_RULES_PATH"])
            
            st.success("Environment variables saved to .env file!")
            time.sleep(1)
            st.rerun()
    
    