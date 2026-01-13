#!/bin/bash
# Setup script for Streamlit deployment

echo "Setting up PHI/PII De-identifier environment..."

# Install spaCy model for NER if available
echo "Installing spaCy models..."
python -m spacy download en_core_web_sm || echo "Failed to download en_core_web_sm"
python -m spacy download en_core_web_lg || echo "Failed to download en_core_web_lg"

# Set environment variables
export STREAMLIT_SERVER_PORT=${PORT:-8501}
export STREAMLIT_SERVER_HEADLESS=true

echo "Setup complete!"
