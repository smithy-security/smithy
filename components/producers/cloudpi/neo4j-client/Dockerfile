FROM python:3.12.2-slim as builder

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Create a working directory for the app
WORKDIR /usr/src/app


# Install Trivy
RUN TRIVY_VERSION=0.40.0 && \
    curl -L "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o trivy.tar.gz && \
    tar zxvf trivy.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy.tar.gz 

# Install pip and wheel, which are required to build many Python packages
RUN pip install --upgrade pip setuptools wheel

# Copy only the requirements file to install dependencies (this helps with caching)
COPY requirements.txt .

# Install Python dependencies without cache to keep the image smaller
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user and switch to it (security best practice)
RUN useradd -ms /bin/bash appuser
USER appuser

# Copy the rest of the application code
COPY --chown=appuser:appuser . .

# Run the application (customize this command based on how your app is run)
CMD ["python", "main.py"]

