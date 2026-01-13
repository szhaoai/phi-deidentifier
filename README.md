# PHI/PII De-identifier Web App

A production-grade de-identification pipeline for sensitive data (PII/PHI) with a user-friendly web interface.
https://phi-deidentifier.streamlit.app/

## Features

- **Multi-mode de-identification**: SAFE_HARBOR and RISK_BASED modes
- **Flexible policies**: HIPAA, GENERIC_PII, and CUSTOM policies
- **Multiple transformation actions**: REDACT, MASK, HASH, TOKENIZE
- **Entity highlighting**: Visual feedback on detected entities
- **Detailed reporting**: Entity-level analysis with confidence scores
- **Regex + NER detection**: Hybrid approach for comprehensive coverage

## Local Development

### Prerequisites

- Python 3.10+
- pip

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Download spaCy models (optional but recommended):
   ```bash
   python -m spacy download en_core_web_sm
   ```
4. Run the app:
   ```bash
   streamlit run demo_app.py
   ```
5. Open your browser to `http://localhost:8501`

## Deployment Options

### Option 1: Streamlit Cloud (Recommended for quick deployment)

**Pros**: Free tier, easy setup, automatic HTTPS, no server management
**Cons**: Limited resources on free tier, public by default

#### Steps:

1. **Create GitHub Repository**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/phi-deidentifier.git
   git push -u origin main
   ```

2. **Deploy to Streamlit Cloud**
   - Go to [Streamlit Cloud](https://streamlit.io/cloud)
   - Sign in with GitHub
   - Click "New app"
   - Select your repository
   - Set the main file path: `demo_app.py`
   - Configure environment (Python version: 3.10)
   - Deploy

3. **Access your app**
   - Streamlit Cloud will provide a URL like `https://yourusername-phi-deidentifier.streamlit.app`
   - Share this URL with others to test the de-identification functions

### Option 2: Heroku

**Pros**: Free tier, easy setup, supports custom domains
**Cons**: Sleeps after 30 minutes of inactivity on free tier

#### Steps:

1. **Install Heroku CLI**
   - Download from [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)

2. **Login and create app**
   ```bash
   heroku login
   heroku create your-app-name
   ```

3. **Deploy**
   ```bash
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

4. **Open your app**
   ```bash
   heroku open
   ```

### Option 3: Docker + Cloud Provider

**Pros**: Full control, scalable, production-ready
**Cons**: More complex setup, costs involved

#### Steps:

1. **Build Docker image**
   ```bash
   docker build -t phi-deidentifier .
   ```

2. **Run locally**
   ```bash
   docker run -p 8501:8501 phi-deidentifier
   ```

3. **Deploy to cloud**
   - Push to container registry (Docker Hub, AWS ECR, etc.)
   - Deploy to cloud service (AWS ECS, Google Cloud Run, Azure Container Instances)

## Configuration

### Environment Variables

- `STREAMLIT_SERVER_PORT`: Port for the Streamlit server (default: 8501)
- `STREAMLIT_SERVER_HEADLESS`: Run in headless mode (default: true for deployment)

### Customization

The app supports different modes and policies:

- **Modes**: `SAFE_HARBOR`, `RISK_BASED`
- **Policies**: `HIPAA`, `GENERIC_PII`, `CUSTOM`
- **Actions**: `REDACT`, `MASK`, `HASH`, `TOKENIZE`

## Entity Types Detected

- Person Names
- Dates
- Phone Numbers
- Email Addresses
- Addresses
- Social Security Numbers (SSN)
- Medical Record Numbers (MRN)
- Passport Numbers
- Credit Card Numbers
- IP Addresses
- And more...

## Security Notes

- The app does not store any input data
- All processing happens in-memory
- Raw values are never displayed in tooltips
- Default action is REDACTION for all detected entities

## Troubleshooting

### Common Issues

1. **spaCy model not found**
   - Install models: `python -m spacy download en_core_web_sm`
   - App will still work with regex-only detection
   
2. **NER Available: False on deployment**
   - This is a common issue with cloud deployments
   - The updated requirements.txt now includes spaCy models directly
   - If still having issues, the app will work with regex-only detection
   - To fix: Ensure `en_core_web_sm` and `en_core_web_lg` models are installed in your deployment environment

2. **Port already in use**
   - Change port: `streamlit run demo_app.py --server.port=8502`

3. **Memory issues on deployment**
   - Consider using a smaller spaCy model or disabling NER
   - Monitor resource usage in your deployment platform

### Performance Optimization

- For high-traffic deployments, consider caching results
- Use smaller spaCy models for faster startup
- Implement rate limiting if needed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Create a GitHub issue
- Check the deployment documentation above
- Review Streamlit and spaCy documentation for platform-specific issues
