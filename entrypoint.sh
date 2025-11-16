#!/bin/bash
set -e

# Validate required environment variables for domain registration
if [ "$DOMAIN_REGISTRATION_ENABLED" = "true" ]; then
    echo "Domain registration is enabled, validating environment variables..."
    
    if [ -z "$CERTBOT_EMAIL" ]; then
        echo "Error: CERTBOT_EMAIL environment variable is required when domain registration is enabled"
        exit 1
    fi
    
    if [ -z "$STATIC_IP" ]; then
        echo "Error: STATIC_IP environment variable is required when domain registration is enabled"
        exit 1
    fi
    
    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        echo "Error: CLOUDFLARE_API_TOKEN environment variable is required when domain registration is enabled"
        exit 1
    fi
    
    if [ -z "$DOMAINS" ]; then
        echo "Error: DOMAINS environment variable is required when domain registration is enabled"
        exit 1
    fi
    
    echo "Domain registration environment variables validated successfully"
fi

# Run the application
echo "Starting vLLM router..."
exec python3 app.py
