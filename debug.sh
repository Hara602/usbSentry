#!/bin/bash
# 获取 dlv 的绝对路径
DLV_PATH=$(which dlv)
# 使用绝对路径运行 dlv（确保 sudo 能找到它）
sudo -E "$DLV_PATH" debug --headless --listen=:2345 --api-version=2 --accept-multiclient "$@"