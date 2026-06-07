#!/usr/bin/env bash
# Excalibur Container Entrypoint
# Sets up authentication based on EXCALIBUR_AUTH_MODE environment variable

set -e

AUTH_MODE="${EXCALIBUR_AUTH_MODE:-manual}"
CCR_CONFIG_DIR="/home/pentester/.claude-code-router"
CCR_CONFIG_FILE="${CCR_CONFIG_DIR}/config.json"
BASHRC_FILE="/home/pentester/.bashrc"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Router configurations for different modes
LOCAL_ROUTER='{"default":"localLLM,openai/gpt-oss-20b","background":"localLLM,openai/gpt-oss-20b","think":"localLLM,qwen/qwen3-coder-30b","longContext":"localLLM,qwen/qwen3-coder-30b","longContextThreshold":60000,"webSearch":"localLLM,openai/gpt-oss-20b"}'

setup_ccr() {
    local mode="$1"
    local api_key="$2"
    local template_file="/app/scripts/ccr-config-template.json"
    local model_name="${OPENROUTER_MODEL:-openai/gpt-5.1}"

    # Create CCR config directory if needed
    mkdir -p "$CCR_CONFIG_DIR"

    # Check if template exists
    if [ ! -f "$template_file" ]; then
        echo -e "${YELLOW}Error: CCR config template not found at $template_file${NC}"
        exit 1
    fi

    # Copy template and substitute placeholders
    cp "$template_file" "$CCR_CONFIG_FILE"

    # Substitute API key (for openrouter mode)
    if [ -n "$api_key" ]; then
        sed -i "s/__OPENROUTER_API_KEY__/${api_key}/g" "$CCR_CONFIG_FILE"
    fi

    # Substitute Router config based on mode (use | as delimiter to avoid conflicts with /)
    if [ "$mode" = "openrouter" ]; then
        local openrouter_router="{\"default\":\"openrouter,${model_name}\",\"background\":\"openrouter,${model_name}\",\"think\":\"openrouter,${model_name}\",\"longContext\":\"openrouter,${model_name}\",\"longContextThreshold\":60000,\"webSearch\":\"openrouter,google/gemini-3-pro-preview\"}"
        sed -i "s|\"__ROUTER_CONFIG__\"|${openrouter_router}|g" "$CCR_CONFIG_FILE"
        local display_model="${model_name}"
    else
        sed -i "s|\"__ROUTER_CONFIG__\"|${LOCAL_ROUTER}|g" "$CCR_CONFIG_FILE"
        local display_model="localLLM (qwen/qwen3-coder-30b, openai/gpt-oss-20b)"
    fi

    # Substitute OpenRouter model placeholder in models list
    sed -i "s|__OPENROUTER_MODEL__|${model_name}|g" "$CCR_CONFIG_FILE"

    echo -e "${BLUE}Starting Claude Code Router...${NC}"

    # Start CCR daemon (nohup to keep it running)
    nohup ccr start > /tmp/ccr.log 2>&1 &

    # Wait for CCR to be ready
    sleep 2

    # Check if CCR is running by testing the port
    if nc -z 127.0.0.1 3456 2>/dev/null; then
        echo -e "${GREEN}CCR daemon running on port 3456${NC}"
    else
        echo -e "${YELLOW}Warning: CCR may not have started properly. Check /tmp/ccr.log${NC}"
    fi

    # Add CCR activation to .bashrc so it persists in interactive shells
    # Remove any existing ccr activation lines first
    sed -i '/# CCR activation/d' "$BASHRC_FILE" 2>/dev/null || true
    sed -i '/eval "$(ccr activate)"/d' "$BASHRC_FILE" 2>/dev/null || true

    # Add ccr activation to bashrc
    echo "# CCR activation for ${mode}" >> "$BASHRC_FILE"
    echo 'eval "$(ccr activate 2>/dev/null)" || true' >> "$BASHRC_FILE"

    # Also export for the current session (will be inherited by exec'd shell)
    eval "$(ccr activate 2>/dev/null)" || true

    echo -e "${GREEN}CCR activated with ${mode} backend${NC}"
    echo -e "${BLUE}Default model: ${display_model}${NC}"
}

echo ""
echo -e "${BLUE}=== Excalibur Authentication ===${NC}"

case "$AUTH_MODE" in
    openrouter)
        if [ -z "$OPENROUTER_API_KEY" ]; then
            echo -e "${YELLOW}Error: OPENROUTER_API_KEY not set${NC}"
            echo "Please run 'make config' and select OpenRouter option"
            exit 1
        fi
        setup_ccr "openrouter" "$OPENROUTER_API_KEY"
        ;;
    local)
        echo -e "${GREEN}Local LLM mode${NC}"
        echo -e "Ensure your local LLM server is running on host.docker.internal:1234"
        setup_ccr "local" ""
        ;;
    anthropic)
        if [ -z "$ANTHROPIC_API_KEY" ]; then
            echo -e "${YELLOW}Warning: ANTHROPIC_API_KEY not set${NC}"
            echo "Please run 'make config' and select Anthropic option"
        else
            echo -e "${GREEN}Using Anthropic API key${NC}"
        fi
        ;;
    gemini)
        if [ -n "$GEMINI_API_KEY" ]; then
            echo -e "${GREEN}Using Gemini API key${NC}"
        elif [ "${GEMINI_API_MODE:-developer}" = "vertex" ] && [ -n "$GOOGLE_CLOUD_PROJECT" ]; then
            echo -e "${GREEN}Using Vertex AI with Application Default Credentials${NC}"
            echo -e "${BLUE}Project: ${GOOGLE_CLOUD_PROJECT}${NC}"
        else
            echo -e "${YELLOW}Error: GEMINI_API_KEY not set${NC}"
            echo "Set a Gemini/Vertex Express key, or configure Vertex AI ADC and GOOGLE_CLOUD_PROJECT"
            exit 1
        fi
        echo -e "${BLUE}Model: ${LLM_MODEL:-gemini-2.5-flash}${NC}"
        ;;
    manual)
        echo -e "${YELLOW}Manual login mode${NC}"
        echo -e "Run ${GREEN}claude login${NC} to authenticate"
        ;;
    *)
        echo -e "${YELLOW}Unknown auth mode: $AUTH_MODE${NC}"
        echo "Defaulting to manual login mode"
        echo -e "Run ${GREEN}claude login${NC} to authenticate"
        ;;
esac

echo -e "${BLUE}=================================${NC}"
echo ""

# Execute the passed command or start bash
# Use bash -l to ensure .bashrc is sourced (for ccr activation)
if [ "$1" = "/bin/bash" ]; then
    exec /bin/bash --login
else
    exec "$@"
fi
