#!/bin/bash
# Install Go 1.22 in WSL2

set -e

GO_VERSION="1.22.10"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"

echo "📦 Downloading Go ${GO_VERSION}..."
wget -q https://go.dev/dl/${GO_TARBALL}

echo "🗑️  Removing old Go installation..."
sudo rm -rf /usr/local/go

echo "📂 Extracting Go to /usr/local/go..."
sudo tar -C /usr/local -xzf ${GO_TARBALL}

echo "🔗 Updating symlink..."
sudo ln -sf /usr/local/go/bin/go /usr/bin/go

echo "🧹 Cleaning up..."
rm ${GO_TARBALL}

echo "✅ Go installed successfully!"
go version

echo ""
echo "Add to your ~/.bashrc or ~/.zshrc:"
echo "export PATH=/usr/local/go/bin:\$PATH"
