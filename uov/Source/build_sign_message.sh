#!/usr/bin/env bash
# Builds sign_message against the UOV/ThesisCode sources, excluding common/main.c
# (which owns its own `int main`). Active scheme is whatever common/parameters.h
# currently selects.
set -euo pipefail
cd "$(dirname "$0")"

gcc -O2 -w \
    -I common -I UOVClassic -I LUOV -I UOVHash \
    $(ls common/*.c | grep -v main.c) \
    UOVClassic/*.c LUOV/*.c UOVHash/*.c \
    sign_message.c -o sign_message -lm

echo "built: $(pwd)/sign_message"
