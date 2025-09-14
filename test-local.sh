#!/bin/bash
mkdir -p ./data/files
mkdir -p ./run
export MBOX_SOCKET_PATH=":8080"
export MBOX_DATA_DIR="./data"
echo "Инициализация mkbox..."
./mkbox -ctl init
echo "Запуск mkbox на http://localhost:8080"
./mkbox -daemon
