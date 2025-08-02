#!/bin/bash
# Installation script for Grafana FLEX Server
# ============================================
# This script installs and configures the Grafana Alertmanager to HackRF FLEX Server Bridge

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="grafana-flexserver"
USER_NAME="grafana-flex"
GROUP_NAME="grafana-flex"
INSTALL_DIR="/opt/grafana-flexserver"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/default/grafana_flexserver"
LOG_FILE="/var/log/grafana_flexserver.log"

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."

    # Update package list
    apt-get update

    # Install Python and pip if not already installed
    apt-get install -y python3 python3-pip python3-venv

    # Install required Python packages
    pip3 install flask requests

    print_success "Dependencies installed"
}

# Create user and group
create_user() {
    print_info "Creating user and group..."

    # Create group if it doesn't exist
    if ! getent group "$GROUP_NAME" > /dev/null 2>&1; then
        groupadd --system "$GROUP_NAME"
        print_success "Created group: $GROUP_NAME"
    else
        print_info "Group $GROUP_NAME already exists"
    fi

    # Create user if it doesn't exist
    if ! getent passwd "$USER_NAME" > /dev/null 2>&1; then
        useradd --system --gid "$GROUP_NAME" --home-dir "$INSTALL_DIR" \
                --shell /bin/false --comment "Grafana FLEX Server" "$USER_NAME"
        print_success "Created user: $USER_NAME"
    else
        print_info "User $USER_NAME already exists"
    fi
}

# Create directories
create_directories() {
    print_info "Creating directories..."

    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    chown "$USER_NAME:$GROUP_NAME" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"

    # Create log directory if it doesn't exist
    touch "$LOG_FILE"
    chown "$USER_NAME:$GROUP_NAME" "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    print_success "Directories created"
}

# Install files
install_files() {
    print_info "Installing service files..."

    # Check if files exist
    if [[ ! -f "grafana_flexserver.py" ]]; then
        print_error "grafana_flexserver.py not found in current directory"
        exit 1
    fi

    # Copy Python script
    cp grafana_flexserver.py "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/grafana_flexserver.py"
    chown "$USER_NAME:$GROUP_NAME" "$INSTALL_DIR/grafana_flexserver.py"

    # Copy systemd service file
    if [[ -f "grafana-flexserver.service" ]]; then
        cp grafana-flexserver.service "$SERVICE_FILE"
        chmod 644 "$SERVICE_FILE"
        print_success "Systemd service file installed"
    else
        print_warning "Service file not found, creating minimal service file"
        create_minimal_service_file
    fi

    # Copy environment file
    if [[ -f "grafana_flexserver.env" ]]; then
        cp grafana_flexserver.env "$ENV_FILE"
        chmod 644 "$ENV_FILE"
        print_success "Environment file installed"
    else
        print_warning "Environment file not found, creating default"
        create_default_env_file
    fi

    print_success "Files installed"
}

# Create minimal service file if not provided
create_minimal_service_file() {
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Grafana Alertmanager to HackRF FLEX Server Bridge
After=network.target
Wants=network.target

[Service]
Type=simple
User=grafana-flex
Group=grafana-flex
WorkingDirectory=/opt/grafana-flexserver
ExecStart=/usr/bin/python3 /opt/grafana-flexserver/grafana_flexserver.py
EnvironmentFile=-/etc/default/grafana_flexserver
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SERVICE_FILE"
}

# Create default environment file if not provided
create_default_env_file() {
    cat > "$ENV_FILE" << 'EOF'
# Grafana FLEX Server Configuration
HACKRF_SERVER_URL=http://localhost:16180
HACKRF_USERNAME=admin
HACKRF_PASSWORD=passw0rd
BIND_HOST=0.0.0.0
BIND_PORT=8080
DEFAULT_CAPCODE=37137
DEFAULT_FREQUENCY=931937500
REQUEST_TIMEOUT=30
LOG_LEVEL=INFO
EOF
    chmod 644 "$ENV_FILE"
}

# Generate SSL certificates
generate_ssl_certificates() {
    print_info "Do you want to generate self-signed SSL certificates for HTTPS? [y/N]"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        print_info "Generating SSL certificates..."

        CERT_DIR="/etc/ssl/certs"
        KEY_DIR="/etc/ssl/private"
        CERT_FILE="$CERT_DIR/grafana-flexserver.crt"
        KEY_FILE="$KEY_DIR/grafana-flexserver.key"

        # Create directories if they don't exist
        mkdir -p "$CERT_DIR" "$KEY_DIR"

        # Generate certificate
        openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" \
            -out "$CERT_FILE" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=grafana-flexserver" \
            2>/dev/null

        # Set permissions
        chmod 600 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        chown "$USER_NAME:$GROUP_NAME" "$KEY_FILE" "$CERT_FILE"

        # Update environment file
        if [[ -f "$ENV_FILE" ]]; then
            sed -i "s|^SSL_CERT_PATH=.*|SSL_CERT_PATH=$CERT_FILE|" "$ENV_FILE"
            sed -i "s|^SSL_KEY_PATH=.*|SSL_KEY_PATH=$KEY_FILE|" "$ENV_FILE"
        fi

        print_success "SSL certificates generated"
        print_warning "These are self-signed certificates for testing only"
        print_warning "Use proper certificates from a CA for production"
    else
        print_info "Skipping SSL certificate generation"
    fi
}

# Configure systemd
configure_systemd() {
    print_info "Configuring systemd service..."

    # Reload systemd
    systemctl daemon-reload

    # Enable service
    systemctl enable "$SERVICE_NAME"

    print_success "Systemd service configured"
}

# Test configuration
test_configuration() {
    print_info "Testing configuration..."

    # Test Python script syntax
    if python3 -m py_compile "$INSTALL_DIR/grafana_flexserver.py"; then
        print_success "Python script syntax is valid"
    else
        print_error "Python script has syntax errors"
        return 1
    fi

    # Test systemd service file
    if systemctl is-enabled "$SERVICE_NAME" &>/dev/null; then
        print_success "Systemd service is enabled"
    else
        print_warning "Systemd service is not enabled"
    fi

    print_success "
