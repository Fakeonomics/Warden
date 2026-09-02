#!/bin/bash
set -euo pipefail

cargo build --release

# Create .AppImage using appimagetool
# Includes .desktop and icon
appimagetool .
