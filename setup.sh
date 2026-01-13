#!/bin/bash
# Setup script for Streamlit deployment

echo "Setting up PHI/PII De-identifier environment..."

# Set environment variables
export STREAMLIT_SERVER_PORT=${PORT:-8501}
export STREAMLIT_SERVER_HEADLESS=true

echo "Setup complete!"
