#ifndef CHAT_SERVER_H
#define CHAT_SERVER_H

#include <crow.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <memory>
#include <regex>
#include "database.h"

struct ClientInfo {
    int user_id;
    std::string username;
    crow::websocket::connection* conn;
    std::chrono::system_clock::time_point last_activity;
};

class ChatServer {
private:
    crow::SimpleApp app;
    Database* db;
    std::unordered_map<crow::websocket::connection*, std::unique_ptr<ClientInfo>> clients;
    std::unordered_map<int, crow::websocket::connection*> user_connections;
    std::mutex clients_mutex;
    std::vector<std::regex> sensitive_words;
    std::mutex sensitive_words_mutex;
    
public:
    ChatServer(Database* database);
    ~ChatServer();
    
    void setupRoutes();
    void setupWebSocket();
    void start(int port = 8080);
    
private:
    // WebSocket 消息处理
    void handleWebSocketMessage(crow::websocket::connection& conn, 
                              const std::string& data, bool is_binary);
    void handleWebSocketClose(crow::websocket::connection& conn, 
                            const std::string& reason);
    void handleWebSocketOpen(crow::websocket::connection& conn);
    
    // 消息处理函数
    void handleLogin(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleLogout(crow::websocket::connection& conn);
    void handleSendMessage(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handlePrivateMessage(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleDeleteMessage(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleGetHistory(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleBlockUser(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleUnblockUser(crow::websocket::connection& conn, const crow::json::rvalue& json);
    void handleStatusChange(crow::websocket::connection& conn, const crow::json::rvalue& json);
    
    // 广播消息
    void broadcastMessage(const std::string& message, crow::websocket::connection* exclude = nullptr);
    void sendToUser(int user_id, const std::string& message);
    void sendOnlineUsersList();
    
    // 工具函数
    std::string filterSensitiveWords(const std::string& text);
    void loadSensitiveWords();
    bool isValidMessageTime(const std::chrono::system_clock::time_point& message_time);
    std::string createJsonResponse(const std::string& type, const crow::json::wvalue& data);
    
    // REST API 路由处理
    crow::response handleRegister(const crow::request& req);
    crow::response handleLoginAPI(const crow::request& req);
    crow::response handleGetMessages(const crow::request& req);
    crow::response handleGetUsers(const crow::request& req);
    
    // CORS 处理
    void setupCORS();
};

#endif // CHAT_SERVER_H
