# Use a base image that already has Node.js and other common tools
FROM mcr.microsoft.com/devcontainers/universal:2

# Install Flutter SDK (already included in universal image, but can specify version)
# If universal image doesn't have your desired Flutter version, you can add:
# RUN sudo apt-get update && sudo apt-get install -y clang cmake ninja-build pkg-config libgtk-3-dev
# RUN git clone https://github.com/flutter/flutter.git /usr/local/flutter
# ENV PATH="/usr/local/flutter/bin:${PATH}"
# RUN flutter precache --web

# Install global npm packages if needed
# RUN npm install -g some-global-package

# Install common system dependencies if needed for Flutter/Node.js native modules
# For example, if you need Android SDK for native builds (not strictly needed for Flutter web/basic CI)
# RUN sudo apt-get update && sudo apt-get install -y default-jdk android-sdk

# Clean up apt caches to reduce image size
RUN sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/*

# Set default working directory (optional, but good practice)
WORKDIR /workspace