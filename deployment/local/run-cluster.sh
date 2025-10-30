#!/bin/bash

# Docker Compose wrapper script for building and running the cluster
# Usage: ./deployment/local/run-cluster.sh <target> [docker-compose-args...]
# Example: ./deployment/local/run-cluster.sh scitt up -d

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if target is provided
if [ $# -lt 1 ]; then
    print_error "Usage: $0 <target> [docker-compose-args...]"
    print_error "Example: $0 scitt up -d"
    print_error "Example: $0 scitt down"
    print_error "Example: $0 scitt logs -f"
    exit 1
fi

TARGET=$1
shift # Remove target from arguments, rest are docker-compose args

if [ ! -f "target/release/${TARGET}" ]; then
    print_error "Target binary 'target/release/${TARGET}' not found!"
    print_error "Available binaries:"
    if [ -d "target/release" ]; then
        ls -1 target/release/ | grep -v '\.' | head -10
    else
        print_error "target/release directory not found. Run 'cargo build --release' first."
    fi
    exit 1
fi

print_info "Using target: ${TARGET}"

export TARGET="${TARGET}"

if [ $# -eq 0 ]; then
    print_info "No docker-compose command specified, defaulting to 'up'"
    set -- up
fi

SHOULD_BUILD=false

if [ "$1" = "up" ]; then
    if ! docker image inspect "pft:${TARGET}" >/dev/null 2>&1; then
        print_info "Docker image 'pft:${TARGET}' not found, building..."
        SHOULD_BUILD=true
    else
        BINARY_TIME=$(stat -c %Y "target/release/${TARGET}" 2>/dev/null || echo 0)
        
        IMAGE_TIME=$(docker image inspect "pft:${TARGET}" --format '{{.Created}}' 2>/dev/null | xargs -I {} date -d {} +%s 2>/dev/null || echo 0)
        
        if [ "$BINARY_TIME" -gt "$IMAGE_TIME" ]; then
            print_info "Binary is newer than Docker image, rebuilding..."
            SHOULD_BUILD=true
        else
            print_info "Docker image 'pft:${TARGET}' is up to date"
        fi
    fi
fi

if [ "$SHOULD_BUILD" = true ]; then
    print_info "Building Docker image with target: ${TARGET}"
    docker build --build-arg TARGET="${TARGET}" -f "${SCRIPT_DIR}/Dockerfile" -t "pft:${TARGET}" .
    
    if [ $? -ne 0 ]; then
        print_error "Docker build failed!"
        exit 1
    fi
    
    print_info "Docker image 'pft:${TARGET}' built successfully"
fi

if [ "$1" = "up" ]; then
    print_info "Cleaning up any existing containers..."
    docker compose -f "${SCRIPT_DIR}/docker-compose.yml" --project-directory "${ROOT_DIR}" down --remove-orphans 2>/dev/null || true
fi

print_info "Running: docker compose -f ${SCRIPT_DIR}/docker-compose.yml --project-directory ${ROOT_DIR} $@"
print_info "Environment: TARGET=${TARGET}"

docker compose -f "${SCRIPT_DIR}/docker-compose.yml" --project-directory "${ROOT_DIR}" "$@"
