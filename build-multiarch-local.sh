#!/bin/bash
# Build script for multi-architecture Docker images (arm64 and amd64) - local build only (no push)
# Note: --load can only load one platform at a time, so this builds for your current platform

set -e

IMAGE_NAME="${IMAGE_NAME:-family-chores}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Detect current platform
CURRENT_PLATFORM=$(docker version --format '{{.Server.Arch}}')
if [ "$CURRENT_PLATFORM" = "amd64" ]; then
    PLATFORM="linux/amd64"
elif [ "$CURRENT_PLATFORM" = "arm64" ] || [ "$CURRENT_PLATFORM" = "aarch64" ]; then
    PLATFORM="linux/arm64"
else
    PLATFORM="linux/amd64,linux/arm64"
    echo "Warning: Unknown platform, building for both amd64 and arm64"
fi

echo "Building Docker image for local use..."
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Platform: ${PLATFORM}"
echo "Note: For true multi-arch builds, use build-multiarch.sh to push to a registry"

# Create a new builder instance if it doesn't exist
if ! docker buildx inspect multiarch-builder >/dev/null 2>&1; then
    echo "Creating new buildx builder instance..."
    docker buildx create --name multiarch-builder --use
    docker buildx inspect --bootstrap
fi

# Build for current platform (load into local Docker)
docker buildx build \
    --platform ${PLATFORM} \
    --tag ${IMAGE_NAME}:${IMAGE_TAG} \
    --load \
    .

echo "Build complete!"
echo "Image ${IMAGE_NAME}:${IMAGE_TAG} is now available locally"

