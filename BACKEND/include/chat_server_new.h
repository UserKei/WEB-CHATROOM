#ifndef CHAT_SERVER_H
#define CHAT_SERVER_H

#include <crow.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <memory>
#include <chrono>
#include <string>
#include <vector>
#include "database.h"

struct ClientConnection {
    crow::websocket::connection* conn;
    int user_id;
    std::string username;
    std::string status;
    std::chrono::steady_clock::time_point last_seen;
};

class ChatServer {
private:
    crow::SimpleApp app;
    Database* db;
    std::unordered_map<crow::websocket::connection*, std::shared_ptr<ClientConnection>> clients;
    std::mutex clients_mutex;
    std::unordered_set<std::string> sensitiveWords;
    
public:
    ChatServer(Database* database);
    ~ChatServer();
    
    void run(int port = 8080);
    
private:
    void setupRoutes();
    void addCORSHeaders(crow::response& res);
    
    // HTTP API 处理方法
    crow::response handleRegister(const crow::request& req);
    crow::response handleLogin(const crow::request& req);
    crow::response handleLogout(const crow::request& req);
    crow::response handleGetMessages(const crow::request& req);
    crow::response handleGetUsers(const crow::request& req);
    
    // WebSocket 消息处理
    void handleWebSocketMessage(crow::websocket::connection* conn, const std::string& data);
    void handleAuthentication(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handleChatMessage(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handlePrivateMessage(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handleStatusChange(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handleTyping(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handleRevokeMessage(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
    void handleBlockUser(std::shared_ptr<ClientConnection> client, const nlohmann::json& data);
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
    int getUserIdFromToken(const crow::request& req);
    void loadSensitiveWords();
    std::string filterProfanity(const std::string& text);
    std::string getCurrentTimestamp();
};

#endif // CHAT_SERVER_H
