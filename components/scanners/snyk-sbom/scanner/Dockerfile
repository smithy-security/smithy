# Start with a base image
FROM ubuntu:22.04

# Install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app
COPY ./entrypoint.sh /exit_0_with_vulns.sh
RUN chmod +x /exit_0_with_vulns.sh

# Create a script to handle architecture detection and binary download
RUN echo '#!/bin/bash \n\
ARCH=$(uname -m) \n\
\n\
BASE="https://github.com/snyk/cli/releases/download/v1.1296.1/snyk-linux"\n\

echo "Detected architecture: $ARCH" \n\
\n\
# Map architecture to download path \n\
if [ "$ARCH" = "x86_64" ]; then \n\
    DOWNLOAD_URL="$BASE" \n\
    echo "Downloading X86 binary..." \n\
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \n\
    DOWNLOAD_URL="$BASE-arm64" \n\
    echo "Downloading ARM64 binary..." \n\
else \n\
    echo "Unsupported architecture: $ARCH" \n\
    exit 1 \n\
fi \n\
\n\
# Download the binary \n\
curl -L -o /bin/snyk $DOWNLOAD_URL \n\
\n\
# Make the binary executable \n\
chmod +x /bin/snyk \n\
\n\
echo "Binary downloaded successfully!" \n\
' > /app/download.sh

# Make the script executable
RUN chmod +x /app/download.sh

# Run the download script when container is built
RUN /app/download.sh

# Install package managers for most supported languages
# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Set up timezone data for packages that might need it
RUN apt-get update && apt-get install -y \
    tzdata \
    && ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata

# Install common dependencies and tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    gnupg \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    build-essential \
    zip \
    unzip \
    pkg-config \
    lsb-release

# Install Python and related tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    && ln -s /usr/bin/python3 /usr/bin/python \
    && python -m pip install --upgrade pip \
    && python -m pip install pipx \
    && python -m pipx ensurepath

# Install Go
RUN curl -OL https://golang.org/dl/go1.20.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz \
    && rm go1.20.5.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Install Swift
RUN apt-get update && apt-get install -y \
    clang \
    libicu-dev \
    libpython3-dev \
    libtinfo5 \
    libncurses5 \
    libxml2 \
    && wget https://download.swift.org/swift-5.8.1-release/ubuntu2204/swift-5.8.1-RELEASE/swift-5.8.1-RELEASE-ubuntu22.04.tar.gz \
    && tar -xzf swift-5.8.1-RELEASE-ubuntu22.04.tar.gz \
    && mv swift-5.8.1-RELEASE-ubuntu22.04 /usr/share/swift \
    && rm swift-5.8.1-RELEASE-ubuntu22.04.tar.gz
ENV PATH=$PATH:/usr/share/swift/usr/bin

# Install PHP and Composer
RUN apt-get update && apt-get install -y \
    php \
    php-cli \
    php-common \
    php-json \
    php-mbstring \
    php-zip \
    php-curl \
    php-xml \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer


# Install .NET SDK
RUN apt update && \
    apt install -y dotnet-sdk-8.0 && \
    apt-get install -y aspnetcore-runtime-8.0

# Install Ruby
RUN apt-get update &&\
    apt-get install -y ruby ruby-dev

# Install Node.js
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash && \
/bin/bash -c 'source "$HOME/.nvm/nvm.sh" && nvm install node && node -v'

# Install Scala sdkman, gradle and sbt
RUN apt-get update &&\
    apt-get install -y scala && \
    curl -s "https://get.sdkman.io" | bash &&\
    /bin/bash -c 'source "/root/.sdkman/bin/sdkman-init.sh" && sdk install sbt && sdk install gradle 8.13'

# Install Java, Gradle, and Maven
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    openjdk-17-jre

# Install Maven
RUN apt install -y maven

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

ENTRYPOINT [ "/exit_0_with_vulns.sh" ]
