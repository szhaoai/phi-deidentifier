#!/bin/bash
# Setup script for Streamlit deployment

echo "Setting up PHI/PII De-identifier environment..."

# Install spaCy models for NER
echo "Installing spaCy models..."
python -m spacy download en_core_web_sm || echo "Failed to download en_core_web_sm"
python -m spacy download en_core_web_lg || echo "Failed to download en_core_web_lg"

# Verify models are installed
echo "Verifying spaCy models..."
python -c "import spacy; spacy.load('en_core_web_sm'); print('en_core_web_sm loaded successfully')" || echo "en_core_web_sm not available"
python -c "import spacy; spacy.load('en_core_web_lg'); print('en_core_web_lg loaded successfully')" || echo "en_core_web_lg not available"

# Set environment variables
export STREAMLIT_SERVER_PORT=${PORT:-8501}
export STREAMLIT_SERVER_HEADLESS=true

echo "Setup complete!"
