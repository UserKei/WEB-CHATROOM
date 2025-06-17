#ifndef CHAT_SERVER_H
#define CHAT_SERVER_H

#include <crow.h>
#include <crow/middlewares/cors.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <memory>
#include <chrono>
#include <string>
#include <vector>
#include "database.h"

using json = nlohmann::json;

struct ClientConnection {
    crow::websocket::connection* conn;
    int user_id;
    std::string username;
    std::string status;
    std::chrono::steady_clock::time_point last_seen;
};

// CORS配置结构（如果需要自定义）
struct CorsConfig {
    std::vector<std::string> allowed_origins;
    std::vector<std::string> allowed_methods;
    std::vector<std::string> allowed_headers;
    bool allow_credentials;
    int max_age;
    
    CorsConfig() {
        allowed_origins = {"*"}; // 开发环境使用通配符
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"};
        allowed_headers = {"Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"};
        allow_credentials = true;
        max_age = 86400;
    }
};

class ChatServer {
private:
    crow::SimpleApp app;
    Database* db;
    std::unordered_map<crow::websocket::connection*, std::shared_ptr<ClientConnection>> clients;
    std::mutex clients_mutex;
    std::unordered_set<std::string> sensitiveWords;
    CorsConfig cors_config; // CORS配置
    
public:
    ChatServer(Database* database);
    ~ChatServer();
    
    void run(int port = 8080);
    
    // 配置方法
    void setCorsConfig(const CorsConfig& config) { cors_config = config; }
    
private:
    void setupRoutes();
    void addCORSHeaders(crow::response& res);
    void addCORSHeaders(crow::response& res, const crow::request& req); // 重载版本，支持动态Origin
    
    // HTTP API 处理方法
    crow::response handleRegister(const crow::request& req);
    crow::response handleLogin(const crow::request& req);
    crow::response handleLogout(const crow::request& req);
    crow::response handleGetMessages(const crow::request& req);
    crow::response handleGetUsers(const crow::request& req);
    
    // WebSocket 消息处理
    void handleWebSocketMessage(crow::websocket::connection* conn, const std::string& data);
    void handleAuthentication(std::shared_ptr<ClientConnection> client, const json& data);
    void handleChatMessage(std::shared_ptr<ClientConnection> client, const json& data);
    void handlePrivateMessage(std::shared_ptr<ClientConnection> client, const json& data);
    void handleStatusChange(std::shared_ptr<ClientConnection> client, const json& data);
    void handleTyping(std::shared_ptr<ClientConnection> client, const json& data);
    void handleRevokeMessage(std::shared_ptr<ClientConnection> client, const json& data);
    void handleBlockUser(std::shared_ptr<ClientConnection> client, const json& data);
    void handleClientDisconnect(crow::websocket::connection* conn);
    
    // 广播方法
    void broadcastToAll(const std::string& message);
    void broadcastToOthers(int excludeUserId, const std::string& message);
    void sendToUser(int userId, const std::string& message);
    void broadcastUserJoined(std::shared_ptr<ClientConnection> client);
    void sendUserList(std::shared_ptr<ClientConnection> client);
    
    // 工具方法
    std::string hashPassword(const std::string& password);
    std::string generateToken(int userId, const std::string& username);
    int validateToken(const std::string& token);
    bool validateTokenWithUserId(const std::string& token, int userId); // 新增：更严格的token验证
    int getUserIdFromToken(const crow::request& req);
    void loadSensitiveWords();
    std::string filterProfanity(const std::string& text);
    std::string getCurrentTimestamp();
    
    // 辅助方法
    bool isOriginAllowed(const std::string& origin) const;
    std::string joinStrings(const std::vector<std::string>& vec, const std::string& delimiter) const;
};

#endif // CHAT_SERVER_H