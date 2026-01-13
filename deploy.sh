#!/bin/bash

# Deployment script for PHI/PII De-identifier

echo "🚀 PHI/PII De-identifier Deployment Script"
echo "=========================================="

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Check if Python is installed
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    echo "❌ Python is not installed. Please install Python first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Function to deploy to Streamlit Cloud
deploy_streamlit() {
    echo "📦 Setting up GitHub repository..."
    
    # Initialize git if not already done
    if [ ! -d ".git" ]; then
        git init
        git add .
        git commit -m "Initial commit: PHI/PII De-identifier with deployment files"
        echo "✅ Git repository initialized"
    else
        echo "✅ Git repository already exists"
    fi
    
    echo ""
    echo "🎯 Next steps for Streamlit Cloud deployment:"
    echo "1. Create a new repository on GitHub: https://github.com/new"
    echo "2. Copy your repository URL (e.g., https://github.com/username/repo.git)"
    echo "3. Run: git remote add origin YOUR_REPOSITORY_URL"
    echo "4. Run: git branch -M main"
    echo "5. Run: git push -u origin main"
    echo "6. Go to https://streamlit.io/cloud and connect your GitHub repository"
    echo "7. Select this repository and set main file to 'demo_app.py'"
    echo "8. Deploy!"
    echo ""
    echo "🌐 Your app will be available at: https://yourusername-reponame.streamlit.app"
}

# Function to deploy to Heroku
deploy_heroku() {
    echo "📦 Setting up Heroku deployment..."
    
    # Check if Heroku CLI is installed
    if ! command -v heroku &> /dev/null; then
        echo "❌ Heroku CLI is not installed. Please install it from: https://devcenter.heroku.com/articles/heroku-cli"
        exit 1
    fi
    
    echo "✅ Heroku CLI found"
    
    # Login to Heroku
    heroku login
    
    # Create app
    echo "🏗️ Creating Heroku app..."
    heroku create
    
    # Set Python buildpack
    heroku buildpacks:set heroku/python
    
    # Deploy
    git add .
    git commit -m "Deploy to Heroku"
    git push heroku main
    
    # Open app
    heroku open
    
    echo "✅ Heroku deployment complete!"
    echo "🌐 Your app is now live on Heroku!"
}

# Function to build and run Docker
deploy_docker() {
    echo "🐳 Building Docker image..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    echo "✅ Docker found"
    
    # Build image
    docker build -t phi-deidentifier .
    
    echo "✅ Docker image built successfully"
    echo ""
    echo "🎯 Next steps for Docker deployment:"
    echo "1. Run locally: docker run -p 8501:8501 phi-deidentifier"
    echo "2. Push to registry: docker tag phi-deidentifier your-registry/phi-deidentifier:latest"
    echo "3. Deploy to cloud service (AWS ECS, Google Cloud Run, etc.)"
}

# Main menu
echo ""
echo "Choose deployment method:"
echo "1) Streamlit Cloud (Recommended)"
echo "2) Heroku"
echo "3) Docker"
echo "4) Local development setup"
echo ""

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        deploy_streamlit
        ;;
    2)
        deploy_heroku
        ;;
    3)
        deploy_docker
        ;;
    4)
        echo "🔧 Setting up local development..."
        pip install -r requirements.txt
        python -m spacy download en_core_web_sm || echo "⚠️ spaCy model download failed, but app will work with regex-only detection"
        echo "✅ Local setup complete!"
        echo "🚀 Run: streamlit run demo_app.py"
        ;;
    *)
        echo "❌ Invalid choice. Please run the script again and select 1, 2, 3, or 4."
        exit 1
        ;;
esac

echo ""
echo "🎉 Deployment setup complete!"
echo "📚 For detailed instructions, see README.md"
