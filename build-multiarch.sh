#!/bin/bash
# Build script for multi-architecture Docker images (arm64 and amd64)

set -e

IMAGE_NAME="${IMAGE_NAME:-ghcr.io/elmerohueso/family-chores}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "Building multi-architecture Docker image..."
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Platforms: linux/amd64,linux/arm64"

# Create a new builder instance if it doesn't exist
if ! docker buildx inspect multiarch-builder >/dev/null 2>&1; then
    echo "Creating new buildx builder instance..."
    docker buildx create --name multiarch-builder --use
    docker buildx inspect --bootstrap
fi

# Build for both platforms
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag ${IMAGE_NAME}:${IMAGE_TAG} \
    --push \
    .

echo "Multi-architecture build complete!"
echo "Image ${IMAGE_NAME}:${IMAGE_TAG} is now available for both amd64 and arm64"

