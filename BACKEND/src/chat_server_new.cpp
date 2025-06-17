#include "chat_server.h"
#include <iostream>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <regex>
#include <set>

using json = nlohmann::json;

ChatServer::ChatServer(Database* database) : db(database) {
    loadSensitiveWords();
}

ChatServer::~ChatServer() {
    // 清理所有连接
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto& client : clients) {
        if (client.second && client.second->user_id > 0) {
            db->updateUserStatus(client.second->user_id, "offline");
        }
    }
}

void ChatServer::setupRoutes() {
    // OPTIONS 预检请求
    CROW_ROUTE(app, "/api/<path>").methods("OPTIONS"_method)
    ([](const crow::request& req, const std::string& path) {
        crow::response res(200);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return res;
    });

    // 主页
    CROW_ROUTE(app, "/")
    ([this](const crow::request& req) {
        crow::response res(200, "text/html", R"(
            <html>
            <head><title>Chat Room Server</title></head>
            <body>
                <h1>多用户聊天室服务器</h1>
                <p>WebSocket 端点: ws://localhost:8080/ws</p>
                <p>API 端点:</p>
                <ul>
                    <li>POST /api/auth/register - 用户注册</li>
                    <li>POST /api/auth/login - 用户登录</li>
                    <li>POST /api/auth/logout - 用户登出</li>
                    <li>GET /api/messages - 获取消息历史</li>
                    <li>GET /api/users - 获取在线用户列表</li>
                </ul>
            </body>
            </html>
        )");
        addCORSHeaders(res);
        return res;
    });

    // 用户注册
    CROW_ROUTE(app, "/api/auth/register").methods("POST"_method)
    ([this](const crow::request& req) {
        return handleRegister(req);
    });

    // 用户登录
    CROW_ROUTE(app, "/api/auth/login").methods("POST"_method)
    ([this](const crow::request& req) {
        return handleLogin(req);
    });

    // 用户登出
    CROW_ROUTE(app, "/api/auth/logout").methods("POST"_method)
    ([this](const crow::request& req) {
        return handleLogout(req);
    });

    // 获取消息历史
    CROW_ROUTE(app, "/api/messages").methods("GET"_method)
    ([this](const crow::request& req) {
        return handleGetMessages(req);
    });

    // 获取在线用户
    CROW_ROUTE(app, "/api/users").methods("GET"_method)
    ([this](const crow::request& req) {
        return handleGetUsers(req);
    });

    // WebSocket 端点
    CROW_ROUTE(app, "/ws")
    .websocket()
    .onopen([this](crow::websocket::connection& conn) {
        CROW_LOG_INFO << "WebSocket connection opened: " << &conn;
        
        auto client = std::make_shared<ClientConnection>();
        client->conn = &conn;
        client->user_id = 0; // 未认证
        client->username = "";
        client->status = "offline";
        client->last_seen = std::chrono::steady_clock::now();
        
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients[&conn] = client;
    })
    .onclose([this](crow::websocket::connection& conn, const std::string& reason) {
        CROW_LOG_INFO << "WebSocket connection closed: " << &conn << " reason: " << reason;
        handleClientDisconnect(&conn);
    })
    .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
        if (!is_binary) {
            handleWebSocketMessage(&conn, data);
        }
    });
}

void ChatServer::addCORSHeaders(crow::response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

crow::response ChatServer::handleRegister(const crow::request& req) {
    try {
        json body = json::parse(req.body);
        
        std::string username = body["username"];
        std::string email = body["email"];
        std::string password = body["password"];
        
        // 验证输入
        if (username.empty() || email.empty() || password.empty()) {
            crow::response res(400);
            addCORSHeaders(res);
            res.write(json{{"error", "All fields are required"}}.dump());
            return res;
        }
        
        // 检查用户名是否存在
        if (db->userExists(username)) {
            crow::response res(409);
            addCORSHeaders(res);
            res.write(json{{"error", "Username already exists"}}.dump());
            return res;
        }
        
        // 创建用户
        std::string hashedPassword = hashPassword(password);
        int userId = db->createUser(username, email, hashedPassword);
        
        if (userId > 0) {
            crow::response res(201);
            addCORSHeaders(res);
            res.write(json{
                {"message", "User registered successfully"},
                {"userId", userId}
            }.dump());
            return res;
        } else {
            crow::response res(500);
            addCORSHeaders(res);
            res.write(json{{"error", "Failed to create user"}}.dump());
            return res;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Register error: " << e.what();
        crow::response res(400);
        addCORSHeaders(res);
        res.write(json{{"error", "Invalid JSON"}}.dump());
        return res;
    }
}

crow::response ChatServer::handleLogin(const crow::request& req) {
    try {
        json body = json::parse(req.body);
        
        std::string username = body["username"];
        std::string password = body["password"];
        
        if (username.empty() || password.empty()) {
            crow::response res(400);
            addCORSHeaders(res);
            res.write(json{{"error", "Username and password are required"}}.dump());
            return res;
        }
        
        std::string hashedPassword = hashPassword(password);
        auto user = db->authenticateUser(username, hashedPassword);
        
        if (user.first > 0) {
            // 生成 token
            std::string token = generateToken(user.first, username);
            
            // 更新用户状态为在线
            db->updateUserStatus(user.first, "online");
            
            crow::response res(200);
            addCORSHeaders(res);
            res.write(json{
                {"message", "Login successful"},
                {"user", {
                    {"id", user.first},
                    {"username", username},
                    {"email", user.second},
                    {"status", "online"}
                }},
                {"token", token}
            }.dump());
            return res;
        } else {
            crow::response res(401);
            addCORSHeaders(res);
            res.write(json{{"error", "Invalid username or password"}}.dump());
            return res;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Login error: " << e.what();
        crow::response res(400);
        addCORSHeaders(res);
        res.write(json{{"error", "Invalid JSON"}}.dump());
        return res;
    }
}

crow::response ChatServer::handleLogout(const crow::request& req) {
    try {
        int userId = getUserIdFromToken(req);
        if (userId > 0) {
            db->updateUserStatus(userId, "offline");
        }
        
        crow::response res(200);
        addCORSHeaders(res);
        res.write(json{{"message", "Logout successful"}}.dump());
        return res;
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Logout error: " << e.what();
        crow::response res(500);
        addCORSHeaders(res);
        res.write(json{{"error", "Logout failed"}}.dump());
        return res;
    }
}

crow::response ChatServer::handleGetMessages(const crow::request& req) {
    try {
        int userId = getUserIdFromToken(req);
        if (userId <= 0) {
            crow::response res(401);
            addCORSHeaders(res);
            res.write(json{{"error", "Unauthorized"}}.dump());
            return res;
        }
        
        auto messages = db->getRecentMessages(3);
        
        json result = json::array();
        for (const auto& msg : messages) {
            result.push_back({
                {"id", msg.id},
                {"senderId", msg.sender_id},
                {"senderName", msg.sender_name},
                {"content", msg.content},
                {"timestamp", msg.timestamp},
                {"type", msg.type},
                {"targetUserId", msg.target_user_id},
                {"isRead", msg.is_read}
            });
        }
        
        crow::response res(200);
        addCORSHeaders(res);
        res.write(json{{"messages", result}}.dump());
        return res;
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Get messages error: " << e.what();
        crow::response res(500);
        addCORSHeaders(res);
        res.write(json{{"error", "Failed to get messages"}}.dump());
        return res;
    }
}

crow::response ChatServer::handleGetUsers(const crow::request& req) {
    try {
        int userId = getUserIdFromToken(req);
        if (userId <= 0) {
            crow::response res(401);
            addCORSHeaders(res);
            res.write(json{{"error", "Unauthorized"}}.dump());
            return res;
        }
        
        auto users = db->getOnlineUsers();
        
        json result = json::array();
        for (const auto& user : users) {
            result.push_back({
                {"id", user.id},
                {"username", user.username},
                {"status", user.status}
            });
        }
        
        crow::response res(200);
        addCORSHeaders(res);
        res.write(json{{"users", result}}.dump());
        return res;
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Get users error: " << e.what();
        crow::response res(500);
        addCORSHeaders(res);
        res.write(json{{"error", "Failed to get users"}}.dump());
        return res;
    }
}

void ChatServer::handleWebSocketMessage(crow::websocket::connection* conn, const std::string& data) {
    try {
        json message = json::parse(data);
        std::string type = message["type"];
        
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.find(conn);
        if (it == clients.end()) {
            return;
        }
        
        auto client = it->second;
        
        if (type == "auth") {
            handleAuthentication(client, message["data"]);
        } else if (client->user_id > 0) { // 已认证用户
            if (type == "message") {
                handleChatMessage(client, message["data"]);
            } else if (type == "private_message") {
                handlePrivateMessage(client, message["data"]);
            } else if (type == "status_change") {
                handleStatusChange(client, message["data"]);
            } else if (type == "typing") {
                handleTyping(client, message["data"]);
            } else if (type == "message_revoked") {
                handleRevokeMessage(client, message["data"]);
            } else if (type == "block_user") {
                handleBlockUser(client, message["data"]);
            }
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "WebSocket message error: " << e.what();
    }
}

void ChatServer::handleAuthentication(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        std::string token = data["token"];
        int userId = validateToken(token);
        
        if (userId > 0) {
            auto userInfo = db->getUserInfo(userId);
            if (userInfo.first > 0) {
                client->user_id = userId;
                client->username = userInfo.second;
                client->status = "online";
                
                db->updateUserStatus(userId, "online");
                
                json response = {
                    {"type", "auth_success"},
                    {"data", {
                        {"userId", userId},
                        {"username", userInfo.second}
                    }},
                    {"timestamp", getCurrentTimestamp()}
                };
                client->conn->send_text(response.dump());
                
                broadcastUserJoined(client);
                sendUserList(client);
                
                CROW_LOG_INFO << "User authenticated: " << userInfo.second << " (" << userId << ")";
            }
        } else {
            json response = {
                {"type", "auth_error"},
                {"data", {{"error", "Invalid token"}}},
                {"timestamp", getCurrentTimestamp()}
            };
            client->conn->send_text(response.dump());
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Authentication error: " << e.what();
    }
}

void ChatServer::handleChatMessage(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        std::string content = data["content"];
        std::string filteredContent = filterProfanity(content);
        
        int messageId = db->saveMessage(client->user_id, client->username, filteredContent, "text");
        
        if (messageId > 0) {
            json message = {
                {"type", "message"},
                {"data", {
                    {"id", messageId},
                    {"senderId", client->user_id},
                    {"senderName", client->username},
                    {"content", filteredContent},
                    {"type", "text"},
                    {"isRead", false},
                    {"canRevoke", true}
                }},
                {"timestamp", getCurrentTimestamp()}
            };
            
            broadcastToAll(message.dump());
            CROW_LOG_INFO << "Message from " << client->username << ": " << filteredContent;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Chat message error: " << e.what();
    }
}

void ChatServer::handlePrivateMessage(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        std::string content = data["content"];
        int targetUserId = data["targetUserId"];
        std::string filteredContent = filterProfanity(content);
        
        int messageId = db->savePrivateMessage(client->user_id, targetUserId, client->username, filteredContent);
        
        if (messageId > 0) {
            json message = {
                {"type", "private_message"},
                {"data", {
                    {"id", messageId},
                    {"senderId", client->user_id},
                    {"senderName", client->username},
                    {"content", filteredContent},
                    {"targetUserId", targetUserId},
                    {"type", "private"},
                    {"isRead", false}
                }},
                {"timestamp", getCurrentTimestamp()}
            };
            
            sendToUser(targetUserId, message.dump());
            client->conn->send_text(message.dump());
            
            CROW_LOG_INFO << "Private message from " << client->username << " to user " << targetUserId;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Private message error: " << e.what();
    }
}

void ChatServer::handleStatusChange(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        std::string status = data["status"];
        
        if (status == "online" || status == "busy" || status == "offline") {
            client->status = status;
            db->updateUserStatus(client->user_id, status);
            
            json message = {
                {"type", "status_change"},
                {"data", {
                    {"userId", client->user_id},
                    {"username", client->username},
                    {"status", status}
                }},
                {"timestamp", getCurrentTimestamp()}
            };
            
            broadcastToAll(message.dump());
            CROW_LOG_INFO << "User " << client->username << " status changed to: " << status;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Status change error: " << e.what();
    }
}

void ChatServer::handleTyping(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        bool isTyping = data["isTyping"];
        
        json message = {
            {"type", "typing"},
            {"data", {
                {"userId", client->user_id},
                {"username", client->username},
                {"isTyping", isTyping}
            }},
            {"timestamp", getCurrentTimestamp()}
        };
        
        broadcastToOthers(client->user_id, message.dump());
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Typing error: " << e.what();
    }
}

void ChatServer::handleRevokeMessage(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        int messageId = data["messageId"];
        
        if (db->canRevokeMessage(messageId, client->user_id)) {
            db->deleteMessage(messageId);
            
            json message = {
                {"type", "message_revoked"},
                {"data", {{"messageId", messageId}}},
                {"timestamp", getCurrentTimestamp()}
            };
            
            broadcastToAll(message.dump());
            CROW_LOG_INFO << "Message " << messageId << " revoked by " << client->username;
        }
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Revoke message error: " << e.what();
    }
}

void ChatServer::handleBlockUser(std::shared_ptr<ClientConnection> client, const json& data) {
    try {
        int targetUserId = data["userId"];
        db->blockUser(client->user_id, targetUserId);
        
        CROW_LOG_INFO << "User " << client->username << " blocked user " << targetUserId;
        
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Block user error: " << e.what();
    }
}

void ChatServer::handleClientDisconnect(crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = clients.find(conn);
    if (it != clients.end()) {
        auto client = it->second;
        
        if (client->user_id > 0) {
            db->updateUserStatus(client->user_id, "offline");
            
            json message = {
                {"type", "user_left"},
                {"data", {
                    {"userId", client->user_id},
                    {"username", client->username}
                }},
                {"timestamp", getCurrentTimestamp()}
            };
            
            broadcastToOthers(client->user_id, message.dump());
            CROW_LOG_INFO << "User disconnected: " << client->username;
        }
        
        clients.erase(it);
    }
}

void ChatServer::broadcastToAll(const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    for (auto& pair : clients) {
        if (pair.second->user_id > 0) {
            try {
                pair.second->conn->send_text(message);
            } catch (const std::exception& e) {
                CROW_LOG_ERROR << "Failed to send message to client: " << e.what();
            }
        }
    }
}

void ChatServer::broadcastToOthers(int excludeUserId, const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    for (auto& pair : clients) {
        if (pair.second->user_id > 0 && pair.second->user_id != excludeUserId) {
            try {
                pair.second->conn->send_text(message);
            } catch (const std::exception& e) {
                CROW_LOG_ERROR << "Failed to send message to client: " << e.what();
            }
        }
    }
}

void ChatServer::sendToUser(int userId, const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    for (auto& pair : clients) {
        if (pair.second->user_id == userId) {
            try {
                pair.second->conn->send_text(message);
                break;
            } catch (const std::exception& e) {
                CROW_LOG_ERROR << "Failed to send message to user " << userId << ": " << e.what();
            }
        }
    }
}

void ChatServer::broadcastUserJoined(std::shared_ptr<ClientConnection> client) {
    json message = {
        {"type", "user_joined"},
        {"data", {
            {"userId", client->user_id},
            {"username", client->username},
            {"status", client->status}
        }},
        {"timestamp", getCurrentTimestamp()}
    };
    
    broadcastToOthers(client->user_id, message.dump());
}

void ChatServer::sendUserList(std::shared_ptr<ClientConnection> client) {
    auto users = db->getOnlineUsers();
    
    json userList = json::array();
    for (const auto& user : users) {
        if (user.id != client->user_id) {
            userList.push_back({
                {"id", user.id},
                {"username", user.username},
                {"status", user.status}
            });
        }
    }
    
    json message = {
        {"type", "user_list"},
        {"data", {{"users", userList}}},
        {"timestamp", getCurrentTimestamp()}
    };
    
    client->conn->send_text(message.dump());
}

std::string ChatServer::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string ChatServer::generateToken(int userId, const std::string& username) {
    std::string data = std::to_string(userId) + ":" + username + ":" + std::to_string(time(nullptr));
    return hashPassword(data).substr(0, 32);
}

int ChatServer::validateToken(const std::string& token) {
    // 简化版token验证
    return 1; // 返回有效的用户ID
}

int ChatServer::getUserIdFromToken(const crow::request& req) {
    std::string authHeader = req.get_header_value("Authorization");
    if (authHeader.empty() || authHeader.find("Bearer ") != 0) {
        return 0;
    }
    
    std::string token = authHeader.substr(7);
    return validateToken(token);
}

void ChatServer::loadSensitiveWords() {
    sensitiveWords = {
        "fuck", "shit", "damn", "hell", "ass",
        "傻逼", "草泥马", "操", "妈的", "白痴",
        "垃圾", "废物", "死", "滚"
    };
}

std::string ChatServer::filterProfanity(const std::string& text) {
    std::string result = text;
    
    for (const auto& word : sensitiveWords) {
        std::regex wordRegex(word, std::regex_constants::icase);
        std::string replacement(word.length(), '*');
        result = std::regex_replace(result, wordRegex, replacement);
    }
    
    return result;
}

std::string ChatServer::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    
    return ss.str();
}

void ChatServer::run(int port) {
    setupRoutes();
    
    CROW_LOG_INFO << "Starting Chat Server on port " << port;
    CROW_LOG_INFO << "WebSocket endpoint: ws://localhost:" << port << "/ws";
    CROW_LOG_INFO << "API endpoints available";
    
    app.port(port).multithreaded().run();
}
