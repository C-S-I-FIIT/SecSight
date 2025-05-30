

<p align="center">
  <img src="assets/logo_secsight.png" alt="SecSight Logo" width="300"/>
</p>

SecSight is a security monitoring and analysis dashboard built with `Streamlit` framework. It integrates various security tools and data sources to provide a unified view of organisation security posture.

The main feature of this project is monitoring of Windows endpoint rule compliance, detection of unnecessary log channels, log channels that are sending logs to SIEM ans which rules are covered and whcih log channels are not enabled and which rules are not covered. 

This is a novel approach to tunning and fine-tunning Windows environments which are monitored, to achieve the most host-rule coverage. In the existing solutions we cannot determine which hosts are compliant with defined rule set and which are not.

## Features

- **SIGMA Rules Dashboard**: View and analyze SIGMA detection rules.
- **Windows Event Log Monitoring**: Winlogbeat configuration analysis and monitoring with SIEM rule set compliance.
- **ATT&CK & Compliance**: MITRE ATT&CK framework integration and compliance monitoring - Dynamic matrix generation on host-rule coverages based on selected filters.
- **Elastic Integration**: Elasticsearch data analysis like number of logs generated by certain Windows log channel.
- **Alerts & Cases**: TheHive integration for alert and case overviews with MITRE ATT&CK data including descriptions, mitigations, etc.
- **Control Panel**: Control of the collection module from GUI.
- **Netbox Integration**: All hosts and info are pulled from NetBox, allowing filtering options.

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- PostgreSQL
- Access to required external services:
  - Elasticsearch
  - TheHive
  - Netbox
  - Windows hosts (for Winlogbeat monitoring)
  - HashiCorp Vault (Secrets Management)

## Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd SecSight
```

2. Create a `.env` file with the following variables:
```env
POSTGRES_USER=postgres
POSTGRES_PASSWORD=changeme
SIGMA_RULES_PATH=/path/to/sigma/rules
```

3. Build and run using Docker Compose:
```bash
docker-compose up -d
```

The application will be available at `http://localhost:8501`

### Manual Installation

1. Create a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run main.py
```

## Configuration

### Database Configuration
The application uses PostgreSQL as its database. The database configuration is managed through environment variables and the docker-compose.yml file. The database schema will be automatically created at the first application run.

### Streamlit Configuration
Streamlit configuration can be customized in `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#E694FF"
```

### HashiCorp Vault Deployment

SecSight uses HashiCorp Vault for secure credential management, particularly for Windows endpoint authentication. The deployment process is automated using Docker and includes several utility scripts.

#### Directory Structure
```
hashicorpvault-deploy/
├── vault/
│   ├── config/      # Vault configuration and certificates
│   ├── policies/    # Vault access policies
│   ├── data/        # Vault data storage
│   └── credentials/ # Generated credentials (auto-created)
├── docker-compose.yaml
├── generate-certs.sh
├── init-vault.sh
└── unseal-vault.sh
```

#### Deployment Steps

1. Generate SSL certificates:
```bash
cd hashicorpvault-deploy
./generate-certs.sh
```

2. Start Vault server:
```bash
docker-compose up -d
```

3. Initialize Vault (this will generate root token and unseal key):
```bash
./init-vault.sh
```

4. Unseal Vault after restarts:
```bash
./unseal-vault.sh
```

#### Important Notes

- The Vault server runs on port 8200 (HTTPS)
- Credentials are stored in `vault/credentials/`:
  - `root_token.txt`: Initial root token for administration
  - `unseal_key.txt`: Key for unsealing the vault
- SSL verification is skipped in development (VAULT_SKIP_VERIFY=true)
- Vault needs to be unsealed after every restart using `unseal-vault.sh`
- All scripts set appropriate permissions for security
- The Vault container uses the official HashiCorp Vault image (version 1.19)

## Data Collection

The application includes a collector script (`collector.py`) that gathers data from various sources. Run it with different options:

```bash
# Collect all data
python collector.py --all

# Collect specific data
python collector.py --mitre        # MITRE ATT&CK data
python collector.py --netbox       # Netbox hosts
python collector.py --winlogbeat   # Winlogbeat configurations
python collector.py --sigma        # SIGMA rules
python collector.py --thehive      # TheHive cases
```

### Collector Options

- `--mitre [-m]`: Collect MITRE ATT&CK data
- `--netbox [-n]`: Get hosts from Netbox
- `--netbox-windows-only`: Only collect Windows hosts
- `--winlogbeat [-w]`: Process Winlogbeat configurations
- `--sigma [-s]`: Process Sigma rules
- `--sigma-rules-path [-p]`: Path to Sigma rules
- `--thehive [-t]`: Sync TheHive cases
- `--verbose [-v]`: Enable verbose logging
- `--all [-a]`: Run all collectors

### Winlogbeat collection

Colletor connects to WIndows devices remotely via `PSExec` or `WinRM` (used as fallback if `PsExec` is not available). It pulls credentials for remote log in to Windows endpoints from **HashiCorp Vault**. Various secrets can be managed through secret metadata - `ip_regex`, which tells collector for which IP or IP range are credentials valid. All info is pulled from NetBox. 

To be able to use `PsExec`, Windows endpoints need to have `SMB` shares enabled and `ADMIN$` share enabled. For `WinRM`, it needs to be allowed via GPO.

Winlogbeat configurations are pulled from Windows devices via one-line powershell scripts (see `./app/scripts`). All Winlogbeat configs are parsed and saved to database. Database also keeps record of the historical compliance data.

## Project Structure

```
SecSight/
├── app/
│   ├── charts/        # Chart components
│   ├── clients/       # API clients
│   ├── collectors/    # Data collectors
│   ├── db/           # Database models
│   ├── mappings/     # Data mappings
│   ├── pages/        # Streamlit pages
│   └── scripts/      # Utility scripts
├── .streamlit/       # Streamlit configuration
├── main.py          # Main application
├── collector.py     # Data collector
├── Dockerfile       # Docker configuration
└── docker-compose.yml
```

## Key Dependencies

- `streamlit`: Web application framework
- `streamlit_nested_layout`: For nested layouts
- `streamlit_authenticator`: Authentication module for Streamlit
- `alembic`: Database migrations
- `loguru`: Logging
- `python-dotenv`: Environment management
- `psycopg2`: PostgreSQL adapter
- `elasticsearch`: Elasticsearch client
- `thehive4py`: TheHive4 API client
- `pynetbox`: Netbox API client
