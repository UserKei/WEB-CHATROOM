#!/bin/bash

# 多用户聊天室服务器构建脚本
echo "=== 构建多用户聊天室服务器 ==="

# 检查依赖
echo "检查依赖..."

if ! command -v brew &> /dev/null; then
    echo "错误: 需要安装 Homebrew"
    echo "请访问 https://brew.sh/ 安装 Homebrew"
    exit 1
fi

# 安装依赖（如果没有安装）
echo "安装必要依赖..."
brew install crow sqlite3 cmake pkg-config jsoncpp openssl

# 创建构建目录
mkdir -p build
cd build

# 使用 CMake 配置项目
echo "配置项目..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# 编译项目
echo "编译项目..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ $? -eq 0 ]; then
    echo "构建成功!"
    echo "可执行文件位置: build/bin/ChatRoomServer"
    echo ""
    echo "运行服务器:"
    echo "  cd build/bin"
    echo "  ./ChatRoomServer [端口号]"
    echo ""
    echo "默认端口: 8080"
    echo "WebSocket: ws://localhost:8080/ws"
    echo "REST API: http://localhost:8080/api/"
else
    echo "构建失败!"
    exit 1
fi
