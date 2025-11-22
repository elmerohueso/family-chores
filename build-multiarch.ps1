# PowerShell build script for multi-architecture Docker images (arm64 and amd64)

$ErrorActionPreference = "Stop"

$IMAGE_NAME = if ($env:IMAGE_NAME) { $env:IMAGE_NAME } else { "ghcr.io/elmerohueso/family-chores" }
$IMAGE_TAG = if ($env:IMAGE_TAG) { $env:IMAGE_TAG } else { "latest" }

Write-Host "Building multi-architecture Docker image..."
Write-Host "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
Write-Host "Platforms: linux/amd64,linux/arm64"

# Create a new builder instance if it doesn't exist
$builderExists = docker buildx inspect multiarch-builder 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Creating new buildx builder instance..."
    docker buildx create --name multiarch-builder --use
    docker buildx inspect --bootstrap
}

# Build for both platforms
docker buildx build `
    --platform linux/amd64,linux/arm64 `
    --tag "${IMAGE_NAME}:${IMAGE_TAG}" `
    --push `
    .

Write-Host "Multi-architecture build complete!"
Write-Host "Image ${IMAGE_NAME}:${IMAGE_TAG} is now available for both amd64 and arm64"

