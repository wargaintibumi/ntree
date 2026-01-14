#!/bin/bash
# Activate NTREE environment

# Activate Python virtual environment
source ~/venvs/sectools/bin/activate

# Add pipx tools to PATH
export PATH="$HOME/.local/bin:$PATH"

# Add tools to PATH
export PATH="$HOME/tools/testssl:$PATH"

# Set NTREE home
export NTREE_HOME="$HOME/ntree"

# Set wordlist paths
export NTREE_WORDLISTS_PATH="$HOME/wordlists"

echo "NTREE environment activated"
echo "Python venv: $(which python)"
echo "NTREE_HOME: $NTREE_HOME"
