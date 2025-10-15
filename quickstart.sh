#!/bin/bash
# Quick start script for py-vuln-scout

set -e

echo "================================"
echo "py-vuln-scout Quick Start"
echo "================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.11"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python 3.11+ is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists${NC}"
fi
echo ""

# Activate venv
echo "Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -e ".[dev]"
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Check Ollama
echo "Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}⚠ Ollama is not installed${NC}"
    echo "  LLM features will not work without Ollama."
    echo "  Install from: https://ollama.ai/"
    echo ""
    OLLAMA_INSTALLED=false
else
    echo -e "${GREEN}✓ Ollama is installed${NC}"
    OLLAMA_INSTALLED=true

    # Check if Ollama is running
    if curl -s http://localhost:11434/api/version &> /dev/null; then
        echo -e "${GREEN}✓ Ollama is running${NC}"

        # Check for default model
        if ollama list | grep -q "qwen2.5-coder:7b"; then
            echo -e "${GREEN}✓ Default model (qwen2.5-coder:7b) is available${NC}"
        else
            echo -e "${YELLOW}⚠ Default model not found${NC}"
            echo "  Pulling qwen2.5-coder:7b (this may take a while)..."
            ollama pull qwen2.5-coder:7b
            echo -e "${GREEN}✓ Model downloaded${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Ollama is not running${NC}"
        echo "  Start Ollama and run this script again."
    fi
fi
echo ""

# Run self-test
echo "Running self-tests..."
if pvs self-test > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Self-tests passed${NC}"
else
    echo -e "${YELLOW}⚠ Some self-tests failed (this is okay if Ollama is not running)${NC}"
fi
echo ""

# Run example analysis
echo "Running example analysis..."
if [ -f "examples/flask_xss.py" ]; then
    echo "Analyzing examples/flask_xss.py with regex engine..."
    pvs analyze examples/flask_xss.py --only regex --format json > /dev/null 2>&1
    echo -e "${GREEN}✓ Example analysis completed${NC}"
else
    echo -e "${YELLOW}⚠ Example file not found${NC}"
fi
echo ""

# Summary
echo "================================"
echo "Setup Complete!"
echo "================================"
echo ""
echo "Quick commands:"
echo "  pvs version              - Show version"
echo "  pvs analyze <file>       - Analyze a Python file"
echo "  pvs analyze --help       - Show all options"
echo ""
echo "Examples:"
echo "  pvs analyze myapp.py --format jsonl"
echo "  pvs analyze myapp.py --only regex"
echo "  pvs analyze myapp.py --no-validate --no-explain"
echo ""

if [ "$OLLAMA_INSTALLED" = false ]; then
    echo -e "${YELLOW}Note: Install Ollama for full LLM-based analysis features${NC}"
    echo "  https://ollama.ai/"
    echo ""
fi

echo "For more information, see README.md"
echo ""
