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
    // 添加 CORS 支持到所有路由的辅助方法
    auto addCORS = [](crow::response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    };
    // 静态文件服务（可选）
    CROW_ROUTE(app, "/")
    ([](const crow::request& req) {
        return crow::response(200, "text/html", R"(
            <html>
            <head><title>Chat Room Server</title></head>
            <body>
                <h1>多用户聊天室服务器</h1>
                <p>WebSocket 端点: ws://localhost:8080/ws</p>
                <p>API 端点:</p>
                <ul>
                    <li>POST /api/register - 用户注册</li>
                    <li>POST /api/login - 用户登录</li>
                    <li>GET /api/messages - 获取消息历史</li>
                    <li>GET /api/users - 获取在线用户列表</li>
                </ul>
            </body>
            </html>
        )");
    });

    // 用户注册
    CROW_ROUTE(app, "/api/register")
    .methods("POST"_method, "OPTIONS"_method)
    ([this](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            return crow::response(200);
        }
        return handleRegister(req);
    });

    // 用户登录
    CROW_ROUTE(app, "/api/login")
    .methods("POST"_method, "OPTIONS"_method)
    ([this](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            return crow::response(200);
        }
        return handleLoginAPI(req);
    });

    // 获取消息历史
    CROW_ROUTE(app, "/api/messages")
    .methods("GET"_method, "OPTIONS"_method)
    ([this](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            return crow::response(200);
        }
        return handleGetMessages(req);
    });

    // 获取在线用户列表
    CROW_ROUTE(app, "/api/users")
    .methods("GET"_method, "OPTIONS"_method)
    ([this](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            return crow::response(200);
        }
        return handleGetUsers(req);
    });
}

void ChatServer::setupWebSocket() {
    CROW_WEBSOCKET_ROUTE(app, "/ws")
    .onopen([this](crow::websocket::connection& conn) {
        handleWebSocketOpen(conn);
    })
    .onclose([this](crow::websocket::connection& conn, const std::string& reason, uint16_t code) {
        handleWebSocketClose(conn, reason);
    })
    .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
        handleWebSocketMessage(conn, data, is_binary);
    });
}

void ChatServer::start(int port) {
    setupRoutes();
    setupWebSocket();
    
    std::cout << "启动聊天室服务器，端口: " << port << std::endl;
    app.port(port).multithreaded().run();
}

void ChatServer::handleWebSocketOpen(crow::websocket::connection& conn) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    clients[&conn] = std::make_unique<ClientInfo>();
    clients[&conn]->conn = &conn;
    clients[&conn]->user_id = 0; // 未登录
    clients[&conn]->last_activity = std::chrono::system_clock::now();
    
    std::cout << "新的WebSocket连接建立" << std::endl;
}

void ChatServer::handleWebSocketClose(crow::websocket::connection& conn, const std::string& reason) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = clients.find(&conn);
    if (it != clients.end() && it->second && it->second->user_id > 0) {
        // 更新用户状态为离线
        db->updateUserStatus(it->second->user_id, "offline");
        user_connections.erase(it->second->user_id);
        
        std::cout << "用户 " << it->second->username << " 断开连接" << std::endl;
        
        // 通知其他用户
        sendOnlineUsersList();
    }
    
    clients.erase(&conn);
}

void ChatServer::handleWebSocketMessage(crow::websocket::connection& conn, 
                                      const std::string& data, bool is_binary) {
    if (is_binary) return;
    
    try {
        auto json = crow::json::load(data);
        if (!json) {
            conn.send_text(R"({"type":"error","message":"Invalid JSON"})");
            return;
        }
        
        std::string type = json["type"].s();
        
        if (type == "login") {
            handleLogin(conn, json);
        } else if (type == "logout") {
            handleLogout(conn);
        } else if (type == "send_message") {
            handleSendMessage(conn, json);
        } else if (type == "private_message") {
            handlePrivateMessage(conn, json);
        } else if (type == "delete_message") {
            handleDeleteMessage(conn, json);
        } else if (type == "get_history") {
            handleGetHistory(conn, json);
        } else if (type == "block_user") {
            handleBlockUser(conn, json);
        } else if (type == "unblock_user") {
            handleUnblockUser(conn, json);
        } else if (type == "status_change") {
            handleStatusChange(conn, json);
        } else {
            conn.send_text(R"({"type":"error","message":"Unknown message type"})");
        }
    } catch (const std::exception& e) {
        conn.send_text(R"({"type":"error","message":"Message processing error"})");
        std::cerr << "WebSocket message error: " << e.what() << std::endl;
    }
}

void ChatServer::handleLogin(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::string username = json["username"].s();
    std::string password_hash = json["password_hash"].s();
    
    User* user = db->authenticateUser(username, password_hash);
    if (!user) {
        conn.send_text(R"({"type":"login_failed","message":"Invalid credentials"})");
        return;
    }
    
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it != clients.end()) {
        it->second->user_id = user->id;
        it->second->username = user->username;
        user_connections[user->id] = &conn;
        
        // 更新用户在线状态
        db->updateUserStatus(user->id, "online");
        
        // 发送登录成功消息
        crow::json::wvalue response;
        response["type"] = "login_success";
        response["user_id"] = user->id;
        response["username"] = user->username;
        response["email"] = user->email;
        response["status"] = user->status;
        
        conn.send_text(response.dump());
        
        // 发送最近消息历史
        auto messages = db->getRecentMessages(50);
        crow::json::wvalue history_response;
        history_response["type"] = "message_history";
        history_response["messages"] = crow::json::wvalue::list();
        
        auto blocked_users = db->getBlockedUsers(user->id);
        std::set<int> blocked_set(blocked_users.begin(), blocked_users.end());
        
        int i = 0;
        for (const auto& msg : messages) {
            if (blocked_set.find(msg.sender_id) == blocked_set.end()) {
                history_response["messages"][i]["id"] = msg.id;
                history_response["messages"][i]["sender_id"] = msg.sender_id;
                history_response["messages"][i]["sender_username"] = msg.sender_username;
                history_response["messages"][i]["content"] = msg.content;
                history_response["messages"][i]["message_type"] = msg.message_type;
                history_response["messages"][i]["timestamp"] = ""; // 需要转换时间格式
                i++;
            }
        }
        
        conn.send_text(history_response.dump());
        
        // 通知所有用户更新在线列表
        sendOnlineUsersList();
        
        std::cout << "用户 " << username << " 登录成功" << std::endl;
    }
    
    delete user;
}

void ChatServer::handleLogout(crow::websocket::connection& conn) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it != clients.end() && it->second && it->second->user_id > 0) {
        db->updateUserStatus(it->second->user_id, "offline");
        user_connections.erase(it->second->user_id);
        
        std::cout << "用户 " << it->second->username << " 登出" << std::endl;
        
        it->second->user_id = 0;
        it->second->username.clear();
        
        sendOnlineUsersList();
    }
}

void ChatServer::handleSendMessage(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    std::string content = json["content"].s();
    content = filterSensitiveWords(content);
    
    // 保存消息到数据库
    if (db->saveMessage(it->second->user_id, 0, content, "public")) {
        // 广播消息给所有在线用户
        crow::json::wvalue broadcast;
        broadcast["type"] = "new_message";
        broadcast["sender_id"] = it->second->user_id;
        broadcast["sender_username"] = it->second->username;
        broadcast["content"] = content;
        broadcast["message_type"] = "public";
        broadcast["timestamp"] = ""; // 当前时间
        
        broadcastMessage(broadcast.dump());
    } else {
        conn.send_text(R"({"type":"error","message":"Failed to save message"})");
    }
}

void ChatServer::handlePrivateMessage(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    int receiver_id = json["receiver_id"].i();
    std::string content = json["content"].s();
    content = filterSensitiveWords(content);
    
    // 检查是否被对方屏蔽
    if (db->isUserBlocked(receiver_id, it->second->user_id)) {
        conn.send_text(R"({"type":"error","message":"You are blocked by this user"})");
        return;
    }
    
    // 保存私聊消息
    if (db->saveMessage(it->second->user_id, receiver_id, content, "private")) {
        crow::json::wvalue message;
        message["type"] = "private_message";
        message["sender_id"] = it->second->user_id;
        message["sender_username"] = it->second->username;
        message["receiver_id"] = receiver_id;
        message["content"] = content;
        message["timestamp"] = "";
        
        // 发送给接收者
        sendToUser(receiver_id, message.dump());
        
        // 确认发送成功给发送者
        conn.send_text(R"({"type":"message_sent","message":"Private message sent"})");
    } else {
        conn.send_text(R"({"type":"error","message":"Failed to save private message"})");
    }
}

void ChatServer::handleDeleteMessage(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    int message_id = json["message_id"].i();
    
    if (db->deleteMessage(message_id, it->second->user_id)) {
        // 通知所有用户消息被删除
        crow::json::wvalue broadcast;
        broadcast["type"] = "message_deleted";
        broadcast["message_id"] = message_id;
        broadcast["deleted_by"] = it->second->user_id;
        
        broadcastMessage(broadcast.dump());
        
        conn.send_text(R"({"type":"success","message":"Message deleted"})");
    } else {
        conn.send_text(R"({"type":"error","message":"Cannot delete message (time expired or not your message)"})");
    }
}

void ChatServer::handleGetHistory(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    int limit = json.has("limit") ? json["limit"].i() : 50;
    auto messages = db->getRecentMessages(limit);
    
    crow::json::wvalue response;
    response["type"] = "message_history";
    response["messages"] = crow::json::wvalue::list();
    
    auto blocked_users = db->getBlockedUsers(it->second->user_id);
    std::set<int> blocked_set(blocked_users.begin(), blocked_users.end());
    
    int i = 0;
    for (const auto& msg : messages) {
        if (blocked_set.find(msg.sender_id) == blocked_set.end()) {
            response["messages"][i]["id"] = msg.id;
            response["messages"][i]["sender_id"] = msg.sender_id;
            response["messages"][i]["sender_username"] = msg.sender_username;
            response["messages"][i]["content"] = msg.content;
            response["messages"][i]["message_type"] = msg.message_type;
            response["messages"][i]["timestamp"] = "";
            i++;
        }
    }
    
    conn.send_text(response.dump());
}

void ChatServer::handleBlockUser(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    int blocked_user_id = json["blocked_user_id"].i();
    
    if (db->blockUser(it->second->user_id, blocked_user_id)) {
        conn.send_text(R"({"type":"success","message":"User blocked"})");
    } else {
        conn.send_text(R"({"type":"error","message":"Failed to block user"})");
    }
}

void ChatServer::handleUnblockUser(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    int blocked_user_id = json["blocked_user_id"].i();
    
    if (db->unblockUser(it->second->user_id, blocked_user_id)) {
        conn.send_text(R"({"type":"success","message":"User unblocked"})");
    } else {
        conn.send_text(R"({"type":"error","message":"Failed to unblock user"})");
    }
}

void ChatServer::handleStatusChange(crow::websocket::connection& conn, const crow::json::rvalue& json) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(&conn);
    if (it == clients.end() || !it->second || it->second->user_id == 0) {
        conn.send_text(R"({"type":"error","message":"Not logged in"})");
        return;
    }
    
    std::string status = json["status"].s();
    
    if (status == "online" || status == "busy" || status == "offline") {
        if (db->updateUserStatus(it->second->user_id, status)) {
            sendOnlineUsersList();
            conn.send_text(R"({"type":"success","message":"Status updated"})");
        } else {
            conn.send_text(R"({"type":"error","message":"Failed to update status"})");
        }
    } else {
        conn.send_text(R"({"type":"error","message":"Invalid status"})");
    }
}

void ChatServer::broadcastMessage(const std::string& message, crow::websocket::connection* exclude) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    for (auto& client : clients) {
        if (client.first != exclude && client.second && client.second->user_id > 0) {
            try {
                client.first->send_text(message);
            } catch (const std::exception& e) {
                std::cerr << "Failed to send message to client: " << e.what() << std::endl;
            }
        }
    }
}

void ChatServer::sendToUser(int user_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = user_connections.find(user_id);
    if (it != user_connections.end()) {
        try {
            it->second->send_text(message);
        } catch (const std::exception& e) {
            std::cerr << "Failed to send message to user " << user_id << ": " << e.what() << std::endl;
        }
    }
}

void ChatServer::sendOnlineUsersList() {
    auto online_users = db->getOnlineUsers();
    
    crow::json::wvalue response;
    response["type"] = "online_users";
    response["users"] = crow::json::wvalue::list();
    
    for (size_t i = 0; i < online_users.size(); ++i) {
        response["users"][i]["id"] = online_users[i].id;
        response["users"][i]["username"] = online_users[i].username;
        response["users"][i]["status"] = online_users[i].status;
        response["users"][i]["avatar_url"] = online_users[i].avatar_url;
    }
    
    broadcastMessage(response.dump());
}

std::string ChatServer::filterSensitiveWords(const std::string& text) {
    std::lock_guard<std::mutex> lock(sensitive_words_mutex);
    
    std::string filtered_text = text;
    for (const auto& regex : sensitive_words) {
        filtered_text = std::regex_replace(filtered_text, regex, "***");
    }
    
    return filtered_text;
}

void ChatServer::loadSensitiveWords() {
    auto words = db->getSensitiveWords();
    
    std::lock_guard<std::mutex> lock(sensitive_words_mutex);
    sensitive_words.clear();
    
    // 添加一些默认敏感词
    if (words.empty()) {
        db->addSensitiveWord("shit");
        db->addSensitiveWord("fuck");
        db->addSensitiveWord("damn");
        words = db->getSensitiveWords();
    }
    
    for (const auto& word : words) {
        try {
            sensitive_words.emplace_back(word, std::regex_constants::icase);
        } catch (const std::exception& e) {
            std::cerr << "Failed to compile regex for word: " << word << std::endl;
        }
    }
}

std::string ChatServer::createJsonResponse(const std::string& type, const crow::json::wvalue& data) {
    crow::json::wvalue response;
    response["type"] = type;
    response["data"] = data;
    return response.dump();
}

// REST API 实现
crow::response ChatServer::handleRegister(const crow::request& req) {
    try {
        auto json = crow::json::load(req.body);
        if (!json) {
            return crow::response(400, "Invalid JSON");
        }
        
        std::string username = json["username"].s();
        std::string password = json["password"].s();
        std::string email = json["email"].s();
        
        // 简单的密码哈希（实际项目中应使用更安全的方法）
        std::hash<std::string> hasher;
        std::string password_hash = std::to_string(hasher(password + "salt"));
        
        if (db->createUser(username, password_hash, email)) {
            crow::json::wvalue response;
            response["success"] = true;
            response["message"] = "User registered successfully";
            return crow::response(200, response.dump());
        } else {
            crow::json::wvalue response;
            response["success"] = false;
            response["message"] = "Failed to register user (username or email may already exist)";
            return crow::response(400, response.dump());
        }
    } catch (const std::exception& e) {
        crow::json::wvalue response;
        response["success"] = false;
        response["message"] = "Registration error";
        return crow::response(500, response.dump());
    }
}

crow::response ChatServer::handleLoginAPI(const crow::request& req) {
    try {
        auto json = crow::json::load(req.body);
        if (!json) {
            return crow::response(400, "Invalid JSON");
        }
        
        std::string username = json["username"].s();
        std::string password = json["password"].s();
        
        std::hash<std::string> hasher;
        std::string password_hash = std::to_string(hasher(password + "salt"));
        
        User* user = db->authenticateUser(username, password_hash);
        if (user) {
            crow::json::wvalue response;
            response["success"] = true;
            response["user"]["id"] = user->id;
            response["user"]["username"] = user->username;
            response["user"]["email"] = user->email;
            response["user"]["status"] = user->status;
            response["password_hash"] = password_hash; // 用于WebSocket认证
            
            delete user;
            return crow::response(200, response.dump());
        } else {
            crow::json::wvalue response;
            response["success"] = false;
            response["message"] = "Invalid credentials";
            return crow::response(401, response.dump());
        }
    } catch (const std::exception& e) {
        crow::json::wvalue response;
        response["success"] = false;
        response["message"] = "Login error";
        return crow::response(500, response.dump());
    }
}

crow::response ChatServer::handleGetMessages(const crow::request& req) {
    auto messages = db->getRecentMessages(100);
    
    crow::json::wvalue response;
    response["messages"] = crow::json::wvalue::list();
    
    for (size_t i = 0; i < messages.size(); ++i) {
        response["messages"][i]["id"] = messages[i].id;
        response["messages"][i]["sender_id"] = messages[i].sender_id;
        response["messages"][i]["sender_username"] = messages[i].sender_username;
        response["messages"][i]["content"] = messages[i].content;
        response["messages"][i]["message_type"] = messages[i].message_type;
        response["messages"][i]["timestamp"] = "";
    }
    
    return crow::response(200, response.dump());
}

crow::response ChatServer::handleGetUsers(const crow::request& req) {
    auto users = db->getOnlineUsers();
    
    crow::json::wvalue response;
    response["users"] = crow::json::wvalue::list();
    
    for (size_t i = 0; i < users.size(); ++i) {
        response["users"][i]["id"] = users[i].id;
        response["users"][i]["username"] = users[i].username;
        response["users"][i]["status"] = users[i].status;
        response["users"][i]["avatar_url"] = users[i].avatar_url;
    }
    
    return crow::response(200, response.dump());
}
