#!/usr/bin/env bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.test.yml"
API_DIR="packages/api/src"
CLI_DIR="packages/cli/src"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup
cleanup() {
    print_info "Cleaning up test environment..."
    docker-compose -f $COMPOSE_FILE down -v 2>/dev/null || true
    # Kill any remaining processes on test ports
    lsof -ti:3001 | xargs kill -9 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Function to start services
start_services() {
    print_info "Starting test services (Redis, Centrifugo)..."
    docker-compose -f $COMPOSE_FILE up -d --wait
    print_success "Services started successfully"
}

# Function to run API tests
run_api_tests() {
    print_info "Running API tests..."

    export JWT_SECRET="test-jwt-secret-for-testing-only"
    export REDIS_URL="redis://localhost:6380"
    export CENTRIFUGO_API_URL="http://localhost:8000/api"
    export CENTRIFUGO_API_KEY="test-api-key-for-testing"
    export CLAWKEY_API_BASE="http://localhost:9000"
    export CLAW_DEV_MODE="true"
    
    # Get list of test files
    local test_files=(
        "$API_DIR/auth.test.ts"
        "$API_DIR/proxy.test.ts"
        "$API_DIR/permissions.test.ts"
        "$API_DIR/publish.test.ts"
        "$API_DIR/advertise.test.ts"
        "$API_DIR/profile.test.ts"
        "$API_DIR/utils.test.ts"
        "$API_DIR/security.test.ts"
        "$API_DIR/edge-cases.test.ts"
        "$API_DIR/apps.test.ts"
    )
    
    local failed=0
    local passed=0
    local port=3001
    
    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            print_info "Running $(basename $test_file) on port $port..."
            
            # Kill any process on the current port and wait for it to be free
            for pid in $(lsof -ti:$port 2>/dev/null); do
                kill -9 $pid 2>/dev/null || true
            done
            # Also kill any lingering bun test processes
            pkill -9 -f "bun test" 2>/dev/null || true
            sleep 2
            while lsof -ti:$port >/dev/null 2>&1; do
                print_info "Waiting for port $port to be free..."
                sleep 1
            done
            
            # Run test with dynamic port
            if PORT=$port bun test "$test_file" --timeout 30000 2>&1; then
                print_success "$(basename $test_file) passed"
                ((passed++))
            else
                print_error "$(basename $test_file) failed"
                ((failed++))
            fi
            
            # Increment port for next test
            ((port++))
        else
            print_warning "Test file not found: $test_file"
        fi
    done
    
    print_info "API Tests: $passed passed, $failed failed"
    return $failed
}

# Function to run CLI tests
run_cli_tests() {
    print_info "Running CLI tests..."
    
    # First start a test server in the background
    print_info "Starting test API server for CLI tests..."
    
    # Wait for port to be free
    while lsof -ti:3001 >/dev/null 2>&1; do
        sleep 0.5
    done
    
    # Export test environment variables (use test services)
    export PORT=3001
    export JWT_SECRET="test-jwt-secret-for-testing-only"
    export REDIS_URL="redis://localhost:6380"
    export CENTRIFUGO_API_URL="http://localhost:8000/api"
    export CENTRIFUGO_API_KEY="test-api-key-for-testing"
    export CLAWKEY_API_BASE="http://localhost:9000"
    export CLAW_DEV_MODE="true"
    
    # Start server in background
    bun run packages/api/src/index.ts &
    local server_pid=$!
    
    # Wait for server to start
    print_info "Waiting for API server to start..."
    for i in {1..30}; do
        if curl -s http://localhost:3001/health >/dev/null 2>&1; then
            print_success "API server is ready"
            break
        fi
        sleep 1
    done
    
    # Get list of test files
    local test_files=(
        "$CLI_DIR/global-options.test.ts"
        "$CLI_DIR/auth-commands.test.ts"
        "$CLI_DIR/publish-commands.test.ts"
        "$CLI_DIR/subscription-commands.test.ts"
        "$CLI_DIR/permission-commands.test.ts"
        "$CLI_DIR/advertising-commands.test.ts"
        "$CLI_DIR/e2e.test.ts"
        "$CLI_DIR/app-commands.test.ts"
    )
    
    local failed=0
    local passed=0
    
    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            print_info "Running $(basename $test_file)..."
            
            if bun test "$test_file" --timeout 60000 2>&1; then
                print_success "$(basename $test_file) passed"
                ((passed++))
            else
                print_error "$(basename $test_file) failed"
                ((failed++))
            fi
        else
            print_warning "Test file not found: $test_file"
        fi
    done
    
    # Kill the server
    kill $server_pid 2>/dev/null || true
    
    print_info "CLI Tests: $passed passed, $failed failed"
    return $failed
}

# Function to run specific test file
run_single_test() {
    local test_file=$1
    
    if [ ! -f "$test_file" ]; then
        print_error "Test file not found: $test_file"
        exit 1
    fi
    
    print_info "Running single test: $(basename $test_file)"
    
    # Wait for port to be free
    while lsof -ti:3001 >/dev/null 2>&1; do
        sleep 0.5
    done
    
    bun test "$test_file" --timeout 30000
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [options] [command]

Commands:
    all                 Run all tests (API + CLI)
    api                 Run API tests only
    cli                 Run CLI tests only
    <test-file>         Run a specific test file
    cleanup             Clean up test services only

Options:
    -h, --help          Show this help message
    --no-docker         Skip Docker services (use if already running)

Examples:
    $0 all              Run all tests
    $0 api              Run API tests only
    $0 cli              Run CLI tests only
    $0 auth.test.ts     Run specific test file
    $0 --no-docker api  Run API tests without starting Docker

EOF
}

# Main script
main() {
    local command="${1:-all}"
    local use_docker=true
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            --no-docker)
                use_docker=false
                shift
                ;;
            *)
                command="$1"
                shift
                ;;
        esac
    done
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    print_info "🧪 Claw.Events Test Runner"
    print_info "=========================="
    
    case $command in
        cleanup)
            cleanup
            print_success "Cleanup complete"
            exit 0
            ;;
        all)
            if [ "$use_docker" = true ]; then
                start_services
            fi
            run_api_tests
            local api_failed=$?
            run_cli_tests
            local cli_failed=$?
            
            if [ $api_failed -eq 0 ] && [ $cli_failed -eq 0 ]; then
                print_success "✅ All tests passed!"
                exit 0
            else
                print_error "❌ Some tests failed"
                exit 1
            fi
            ;;
        api)
            if [ "$use_docker" = true ]; then
                start_services
            fi
            run_api_tests
            exit $?
            ;;
        cli)
            if [ "$use_docker" = true ]; then
                start_services
            fi
            run_cli_tests
            exit $?
            ;;
        *.test.ts)
            if [ "$use_docker" = true ]; then
                start_services
            fi
            run_single_test "$command"
            exit $?
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
