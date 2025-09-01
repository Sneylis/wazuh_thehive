#!/bin/sh

# Обёртка для запуска custom-w2thive.py
# Автоматически определяет путь до Wazuh и вызывает нужный интерпретатор

WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_BASENAME="$(basename "$0")"
DIR_NAME="$(cd "$(dirname "$0")"; pwd -P)"

# Определим WAZUH_PATH
if [ -z "$WAZUH_PATH" ]; then
  WAZUH_PATH="$(cd "$DIR_NAME/.." && pwd)"
fi

PYTHON_SCRIPT="$DIR_NAME/${SCRIPT_BASENAME}.py"

# Защита: проверим, что файл действительно существует
if [ ! -f "$PYTHON_SCRIPT" ]; then
  echo "ERROR: Python script not found: $PYTHON_SCRIPT" >&2
  exit 1
fi

# Запуск
exec "$WAZUH_PATH/$WPYTHON_BIN" "$PYTHON_SCRIPT" "$@"
