#!/usr/bin/env python3
"""
Generate Secure Credentials for AI-SOC Production Deployment
Replaces all default passwords with cryptographically strong credentials

Author: LOVELESS (Elite Security Specialist)
Mission: OPERATION SECURITY-FORTRESS
Date: 2025-10-23
"""

import secrets
import hashlib
import base64
import sys
from pathlib import Path
from datetime import datetime


def generate_password(length=32, include_special=True):
    """Generate cryptographically strong password."""
    if include_special:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
    else:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_base64_key(length=32):
    """Generate base64-encoded random key (Wazuh format)."""
    random_bytes = secrets.token_bytes(length)
    return base64.b64encode(random_bytes).decode('utf-8')


def generate_api_key(prefix="aisoc"):
    """Generate API key with prefix."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def generate_jwt_secret():
    """Generate JWT secret key."""
    return secrets.token_urlsafe(64)


def generate_all_credentials():
    """Generate all production credentials."""
    print("=" * 80)
    print("AI-SOC PRODUCTION CREDENTIALS GENERATOR")
    print("=" * 80)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("⚠️  WARNING: Store these credentials securely!")
    print("   - Use a password manager (1Password, LastPass, etc.)")
    print("   - Enable 2FA where possible")
    print("   - Never commit to version control")
    print("   - Rotate every 90 days")
    print("=" * 80)
    print()

    credentials = {}

    # ========================================================================
    # Wazuh Credentials
    # ========================================================================
    print("## WAZUH CREDENTIALS")
    print("-" * 80)

    credentials["INDEXER_USERNAME"] = "admin"
    credentials["INDEXER_PASSWORD"] = generate_base64_key(32)
    print(f"Wazuh Indexer:")
    print(f"  Username: {credentials['INDEXER_USERNAME']}")
    print(f"  Password: {credentials['INDEXER_PASSWORD']}")
    print()

    credentials["API_USERNAME"] = "wazuh-wui"
    credentials["API_PASSWORD"] = generate_base64_key(32)
    print(f"Wazuh API:")
    print(f"  Username: {credentials['API_USERNAME']}")
    print(f"  Password: {credentials['API_PASSWORD']}")
    print()

    credentials["WEBHOOK_SHARED_SECRET"] = generate_base64_key(32)
    print(f"Webhook Shared Secret (Wazuh -> wazuh-integration):")
    print(f"  {credentials['WEBHOOK_SHARED_SECRET']}")
    print()

    credentials["ORCHESTRATOR_JWT_SECRET_KEY"] = secrets.token_hex(32)
    credentials["ORCHESTRATOR_BOOTSTRAP_API_KEY"] = generate_api_key("aisoc-orch")
    print(f"Response Orchestrator Auth:")
    print(f"  JWT Secret:    {credentials['ORCHESTRATOR_JWT_SECRET_KEY']}")
    print(f"  Bootstrap Key: {credentials['ORCHESTRATOR_BOOTSTRAP_API_KEY']}")
    print()

    # ========================================================================
    # Database Credentials
    # ========================================================================
    print("## DATABASE CREDENTIALS")
    print("-" * 80)

    credentials["POSTGRES_USER"] = "aisoc"
    credentials["POSTGRES_PASSWORD"] = generate_base64_key(32)
    credentials["POSTGRES_DB"] = "aisoc_metadata"
    print(f"PostgreSQL:")
    print(f"  Username: {credentials['POSTGRES_USER']}")
    print(f"  Password: {credentials['POSTGRES_PASSWORD']}")
    print(f"  Database: {credentials['POSTGRES_DB']}")
    print()

    # ========================================================================
    # Redis Credentials
    # ========================================================================
    print("## REDIS CREDENTIALS")
    print("-" * 80)

    credentials["REDIS_PASSWORD"] = generate_base64_key(32)
    print(f"Redis:")
    print(f"  Password: {credentials['REDIS_PASSWORD']}")
    print()

    # ========================================================================
    # SOAR & Monitoring Credentials
    # ========================================================================
    print("## SOAR & MONITORING CREDENTIALS")
    print("-" * 80)

    credentials["MINIO_ROOT_USER"] = "minioadmin"
    credentials["MINIO_ROOT_PASSWORD"] = generate_password(32)
    print(f"MinIO:")
    print(f"  Username: {credentials['MINIO_ROOT_USER']}")
    print(f"  Password: {credentials['MINIO_ROOT_PASSWORD']}")
    print()

    credentials["SHUFFLE_ENCRYPTION_MODIFIER"] = generate_base64_key(32)
    print(f"Shuffle Encryption Modifier:")
    print(f"  {credentials['SHUFFLE_ENCRYPTION_MODIFIER']}")
    print()

    credentials["OPENSEARCH_PASSWORD"] = generate_password(32)
    print(f"OpenSearch (Shuffle):")
    print(f"  Password: {credentials['OPENSEARCH_PASSWORD']}")
    print()

    credentials["GRAFANA_ADMIN_USER"] = "admin"
    credentials["GRAFANA_ADMIN_PASSWORD"] = generate_password(32)
    print(f"Grafana:")
    print(f"  Username: {credentials['GRAFANA_ADMIN_USER']}")
    print(f"  Password: {credentials['GRAFANA_ADMIN_PASSWORD']}")
    print()

    # ========================================================================
    # JWT & API Keys
    # ========================================================================
    print("## API SECURITY")
    print("-" * 80)

    credentials["JWT_SECRET_KEY"] = generate_jwt_secret()
    print(f"JWT Secret Key:")
    print(f"  {credentials['JWT_SECRET_KEY']}")
    print()

    credentials["API_KEY_ADMIN"] = generate_api_key("aisoc")
    credentials["API_KEY_READONLY"] = generate_api_key("aisoc")
    credentials["API_KEY_SERVICE"] = generate_api_key("aisoc")
    print(f"API Keys:")
    print(f"  Admin:     {credentials['API_KEY_ADMIN']}")
    print(f"  ReadOnly:  {credentials['API_KEY_READONLY']}")
    print(f"  Service:   {credentials['API_KEY_SERVICE']}")
    print()

    # ========================================================================
    # Jupyter & Development Tools
    # ========================================================================
    print("## DEVELOPMENT TOOLS")
    print("-" * 80)

    credentials["JUPYTER_TOKEN"] = secrets.token_hex(32)
    print(f"Jupyter Lab:")
    print(f"  Token: {credentials['JUPYTER_TOKEN']}")
    print()

    credentials["PORTAINER_ADMIN_PASSWORD"] = generate_password(32)
    print(f"Portainer:")
    print(f"  Password: {credentials['PORTAINER_ADMIN_PASSWORD']}")
    print()

    # ========================================================================
    # Redis Commander
    # ========================================================================
    credentials["REDIS_COMMANDER_USER"] = "admin"
    credentials["REDIS_COMMANDER_PASSWORD"] = generate_password(24)
    print(f"Redis Commander:")
    print(f"  Username: {credentials['REDIS_COMMANDER_USER']}")
    print(f"  Password: {credentials['REDIS_COMMANDER_PASSWORD']}")
    print()

    # ========================================================================
    # SMTP (Optional)
    # ========================================================================
    print("## EMAIL NOTIFICATIONS (Optional)")
    print("-" * 80)
    print("Configure your SMTP settings manually:")
    print("  SMTP_HOST=smtp.gmail.com")
    print("  SMTP_PORT=587")
    print("  SMTP_USERNAME=your-email@example.com")
    print("  SMTP_PASSWORD=<your-app-specific-password>")
    print()

    print("=" * 80)
    print("CREDENTIAL GENERATION COMPLETE")
    print("=" * 80)
    print()

    return credentials


def write_env_file(credentials, output_path=".env.production"):
    """Write credentials to .env file."""
    output_file = Path(output_path)

    with open(output_file, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# AI-SOC PRODUCTION CREDENTIALS\n")
        f.write("# ============================================================================\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# \n")
        f.write("# ⚠️  CRITICAL SECURITY NOTICE:\n")
        f.write("#   - This file contains production secrets\n")
        f.write("#   - NEVER commit to version control\n")
        f.write("#   - Store securely with encryption\n")
        f.write("#   - Restrict file permissions: chmod 600 .env.production\n")
        f.write("#   - Rotate credentials every 90 days\n")
        f.write("# ============================================================================\n\n")

        f.write("# Wazuh Credentials\n")
        f.write(f"INDEXER_USERNAME={credentials['INDEXER_USERNAME']}\n")
        f.write(f"INDEXER_PASSWORD={credentials['INDEXER_PASSWORD']}\n")
        f.write(f"API_USERNAME={credentials['API_USERNAME']}\n")
        f.write(f"API_PASSWORD={credentials['API_PASSWORD']}\n")
        f.write(f"WEBHOOK_SHARED_SECRET={credentials['WEBHOOK_SHARED_SECRET']}\n\n")

        f.write("# Response Orchestrator Auth\n")
        f.write(f"ORCHESTRATOR_JWT_SECRET_KEY={credentials['ORCHESTRATOR_JWT_SECRET_KEY']}\n")
        f.write(f"ORCHESTRATOR_BOOTSTRAP_API_KEY={credentials['ORCHESTRATOR_BOOTSTRAP_API_KEY']}\n\n")

        f.write("# Database Credentials\n")
        f.write(f"POSTGRES_USER={credentials['POSTGRES_USER']}\n")
        f.write(f"POSTGRES_PASSWORD={credentials['POSTGRES_PASSWORD']}\n")
        f.write(f"POSTGRES_DB={credentials['POSTGRES_DB']}\n")
        f.write("POSTGRES_PORT=5432\n\n")

        f.write("# Redis Credentials\n")
        f.write(f"REDIS_PASSWORD={credentials['REDIS_PASSWORD']}\n")
        f.write("REDIS_PORT=6379\n\n")

        f.write("# SOAR & Monitoring Credentials\n")
        f.write(f"MINIO_ROOT_USER={credentials['MINIO_ROOT_USER']}\n")
        f.write(f"MINIO_ROOT_PASSWORD={credentials['MINIO_ROOT_PASSWORD']}\n")
        f.write(f"SHUFFLE_ENCRYPTION_MODIFIER={credentials['SHUFFLE_ENCRYPTION_MODIFIER']}\n")
        f.write(f"OPENSEARCH_PASSWORD={credentials['OPENSEARCH_PASSWORD']}\n")
        f.write(f"GRAFANA_ADMIN_USER={credentials['GRAFANA_ADMIN_USER']}\n")
        f.write(f"GRAFANA_ADMIN_PASSWORD={credentials['GRAFANA_ADMIN_PASSWORD']}\n\n")

        f.write("# API Security\n")
        f.write(f"AISOC_JWT_SECRET_KEY={credentials['JWT_SECRET_KEY']}\n")
        f.write(f"AISOC_API_KEY_ADMIN={credentials['API_KEY_ADMIN']}\n")
        f.write(f"AISOC_API_KEY_READONLY={credentials['API_KEY_READONLY']}\n")
        f.write(f"AISOC_API_KEY_SERVICE={credentials['API_KEY_SERVICE']}\n\n")

        f.write("# Development Tools\n")
        f.write(f"JUPYTER_TOKEN={credentials['JUPYTER_TOKEN']}\n")
        f.write("JUPYTER_USER=jovyan\n")
        f.write("JUPYTER_PORT=8888\n\n")

        f.write(f"PORTAINER_ADMIN_PASSWORD={credentials['PORTAINER_ADMIN_PASSWORD']}\n")
        f.write("PORTAINER_HTTP_PORT=9000\n")
        f.write("PORTAINER_HTTPS_PORT=9443\n\n")

        f.write(f"REDIS_COMMANDER_USER={credentials['REDIS_COMMANDER_USER']}\n")
        f.write(f"REDIS_COMMANDER_PASSWORD={credentials['REDIS_COMMANDER_PASSWORD']}\n")
        f.write("REDIS_COMMANDER_PORT=8081\n\n")

        f.write("# Security Configuration\n")
        f.write("DEPLOYMENT_ENV=production\n")
        f.write("DEBUG_MODE=false\n")
        f.write("FORCE_HTTPS=true\n")
        f.write("RATE_LIMIT_PROFILE=strict\n")
        f.write("ALLOWED_ORIGINS=https://yourdomain.com\n\n")

        f.write("# Network Configuration\n")
        f.write("MONITOR_INTERFACE=eth0\n")
        f.write("BACKEND_SUBNET=172.24.0.0/24\n")
        f.write("FRONTEND_SUBNET=172.25.0.0/24\n\n")

    print(f"✅ Credentials written to: {output_file}")
    print(f"🔒 Set secure permissions: chmod 600 {output_file}")


def main():
    """Main entry point."""
    print()
    credentials = generate_all_credentials()

    # Ask to write to file
    response = input("\nWrite credentials to .env.production file? (y/N): ")

    if response.lower() == 'y':
        write_env_file(credentials)
        print()
        print("✅ CREDENTIALS GENERATED SUCCESSFULLY")
        print()
        print("Next steps:")
        print("  1. Secure the .env.production file: chmod 600 .env.production")
        print("  2. Backup credentials to password manager")
        print("  3. Copy .env.production to production server")
        print("  4. Restart all services: docker-compose restart")
        print("  5. Verify authentication is working")
        print()
    else:
        print()
        print("⚠️  Credentials NOT saved to file")
        print("   Copy credentials manually or re-run with 'y' to save")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
