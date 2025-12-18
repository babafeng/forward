#!/bin/bash

# Check Root User

# # If you want to run as another user, please modify $EUID to be owned by this user
# if [[ "$EUID" -ne '0' ]]; then
#     echo "$(tput setaf 1)Error: You must run this script as root!$(tput sgr0)"
#     exit 1
# fi

# Set the desired GitHub repository
repo="babafeng/forward"
base_url="https://api.github.com/repos/$repo/releases"

# Function to download and install forward
install_forward() {
    version=$1
    # Detect the operating system
    if [[ "$(uname)" == "Linux" ]]; then
        os="linux"
    elif [[ "$(uname)" == "Darwin" ]]; then
        os="darwin"
    elif [[ "$(uname)" == "MINGW"* ]]; then
        os="windows"
    else
        echo "Unsupported operating system."
        exit 1
    fi

    # Detect the CPU architecture
    arch=$(uname -m)
    case $arch in
    x86_64)
        cpu_arch="amd64"
        ;;
    aarch64)
        cpu_arch="arm64"
        ;;
    arm64)
        cpu_arch="arm64"
        ;;
    *)
        echo "Unsupported CPU architecture. $arch"
        exit 1
        ;;
    esac
    get_download_url="$base_url/tags/$version"
    download_url=$(curl -s "$get_download_url" | grep -Eo "\"browser_download_url\": \".*${os}.*${cpu_arch}.*\"" | awk -F'["]' '{print $4}')

    # Download the binary
    echo "Downloading forward version $version..."
    curl -fsSL -o forward.tar.gz $download_url

    # Extract and install the binary
    echo "Installing forward version $version..."
    tar -xzf forward.tar.gz
    chmod +x forward
    mv forward /usr/local/bin/forward

    echo "forward installation completed: /usr/local/bin/forward version $version"
}

# Retrieve available versions from GitHub API
versions=$(curl -s "$base_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')

# Check if --install option provided
if [[ "$1" == "--install" ]]; then
    # Install the latest version automatically
    latest_version=$(echo "$versions" | head -n 1)
    install_forward $latest_version
else
    # Display available versions to the user
    echo "Available forward versions:"
    select version in $versions; do
        if [[ -n $version ]]; then
            install_forward $version
            break
        else
            echo "Invalid choice! Please select a valid option."
        fi
    done
fi
