#include <iostream>
#include <memory>
#include <signal.h>
#include "database.h"
#include "chat_server.h"

std::unique_ptr<ChatServer> server;
std::unique_ptr<Database> db;

void signalHandler(int signal) {
    std::cout << "\n正在关闭服务器..." << std::endl;
    
    if (server) {
        server.reset();
    }
    
    if (db) {
        db->close();
        db.reset();
    }
    
    exit(0);
}

int main(int argc, char* argv[]) {
    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "=== 多用户聊天室服务器 ===" << std::endl;
    std::cout << "技术栈: C++ Crow + SQLite + WebSocket" << std::endl;
    std::cout << "功能: 多用户聊天、私聊、权限管理、敏感词过滤" << std::endl;
    std::cout << "==============================" << std::endl;
    
    // 初始化数据库
    db = std::make_unique<Database>("chatroom.db");
    if (!db->init()) {
        std::cerr << "数据库初始化失败!" << std::endl;
        return 1;
    }
    
    std::cout << "数据库初始化成功" << std::endl;
    
    // 创建并启动服务器
    server = std::make_unique<ChatServer>(db.get());
    
    // 解析命令行参数获取端口
    int port = 8080;
    if (argc > 1) {
        try {
            port = std::stoi(argv[1]);
        } catch (const std::exception& e) {
            std::cout << "无效端口号，使用默认端口 8080" << std::endl;
            port = 8080;
        }
    }
    
    std::cout << "启动服务器，端口: " << port << std::endl;
    std::cout << "WebSocket 连接地址: ws://localhost:" << port << "/ws" << std::endl;
    std::cout << "REST API 地址: http://localhost:" << port << "/api/" << std::endl;
    std::cout << "按 Ctrl+C 停止服务器" << std::endl;
    
    try {
        server->run(port);
    } catch (const std::exception& e) {
        std::cerr << "服务器启动失败: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
