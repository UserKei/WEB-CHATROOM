#include "chat_server.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <regex>

ChatServer::ChatServer(Database* database) : db(database) {
    loadSensitiveWords();
    setupRoutes();
    setupWebSocket();
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

    // 用户注销
    CROW_ROUTE(app, "/api/auth/logout").methods("POST"_method)
    ([this](const crow::request& req) {
        return handleLogout(req);
    });

    // 获取在线用户列表
    CROW_ROUTE(app, "/api/users/online").methods("GET"_method)
    ([this](const crow::request& req) {
        return handleGetOnlineUsers(req);
    });

    // 获取聊天历史
    CROW_ROUTE(app, "/api/messages").methods("GET"_method)
    ([this](const crow::request& req) {
        return handleGetMessages(req);
    });

    // CORS 预检请求处理
    CROW_ROUTE(app, "/api/<path>").methods("OPTIONS"_method)
    ([](const crow::request&, const std::string&) {
        crow::response res(200);
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return res;
    });
}

void ChatServer::setupWebSocket() {
    CROW_ROUTE(app, "/ws")
    .websocket(&app)
    .onopen([this](crow::websocket::connection& conn) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto client_info = std::make_shared<ClientInfo>();
        client_info->conn = &conn;
        client_info->user_id = 0; // 未认证
        client_info->last_activity = std::chrono::system_clock::now();
        clients[&conn] = client_info;
        
        CROW_LOG_INFO << "WebSocket connection opened";
    })
    .onclose([this](crow::websocket::connection& conn, const std::string& reason) {
        handleDisconnect(&conn);
        CROW_LOG_INFO << "WebSocket connection closed: " << reason;
    })
    .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
        if (!is_binary) {
            handleMessage(&conn, data);
        }
    });
}

crow::response ChatServer::handleRegister(const crow::request& req) {
    crow::response res;
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Content-Type", "application/json");

    try {
        auto json_data = crow::json::load(req.body);
        if (!json_data) {
            res.code = 400;
            res.body = R"({"error":"Invalid JSON"})";
            return res;
        }

        std::string username = json_data["username"].s();
        std::string email = json_data["email"].s();
        std::string password = json_data["password"].s();

        if (username.empty() || email.empty() || password.empty()) {
            res.code = 400;
            res.body = R"({"error":"Missing required fields"})";
            return res;
        }

        // 检查用户名是否已存在
        if (db->getUserByUsername(username).id != 0) {
            res.code = 409;
            res.body = R"({"error":"Username already exists"})";
            return res;
        }

        // 创建用户
        User user;
        user.username = username;
        user.email = email;
        user.password_hash = hashPassword(password);
        user.status = "offline";
        user.created_at = std::time(nullptr);

        if (db->createUser(user)) {
            res.code = 201;
            res.body = R"({"message":"User created successfully"})";
        } else {
            res.code = 500;
            res.body = R"({"error":"Failed to create user"})";
        }
    } catch (const std::exception& e) {
        res.code = 500;
        res.body = R"({"error":"Internal server error"})";
    }

    return res;
}

crow::response ChatServer::handleLogin(const crow::request& req) {
    crow::response res;
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Content-Type", "application/json");

    try {
        auto json_data = crow::json::load(req.body);
        if (!json_data) {
            res.code = 400;
            res.body = R"({"error":"Invalid JSON"})";
            return res;
        }

        std::string username = json_data["username"].s();
        std::string password = json_data["password"].s();

        if (username.empty() || password.empty()) {
            res.code = 400;
            res.body = R"({"error":"Missing username or password"})";
            return res;
        }

        User user = db->getUserByUsername(username);
        if (user.id == 0 || !verifyPassword(password, user.password_hash)) {
            res.code = 401;
            res.body = R"({"error":"Invalid credentials"})";
            return res;
        }

        // 生成token
        std::string token = generateToken(user.id);
        
        // 更新用户状态为在线
        db->updateUserStatus(user.id, "online");

        crow::json::wvalue response;
        response["user"]["id"] = user.id;
        response["user"]["username"] = user.username;
        response["user"]["email"] = user.email;
        response["user"]["status"] = "online";
        response["token"] = token;

        res.code = 200;
        res.body = response.dump();
    } catch (const std::exception& e) {
        res.code = 500;
        res.body = R"({"error":"Internal server error"})";
    }

    return res;
}

crow::response ChatServer::handleLogout(const crow::request& req) {
    crow::response res;
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Content-Type", "application/json");

    try {
        std::string auth_header = req.get_header_value("Authorization");
        if (auth_header.substr(0, 7) == "Bearer ") {
            std::string token = auth_header.substr(7);
            int user_id = validateToken(token);
            
            if (user_id > 0) {
                db->updateUserStatus(user_id, "offline");
                // 从连接列表中移除用户
                removeUserConnections(user_id);
            }
        }

        res.code = 200;
        res.body = R"({"message":"Logged out successfully"})";
    } catch (const std::exception& e) {
        res.code = 500;
        res.body = R"({"error":"Internal server error"})";
    }

    return res;
}

crow::response ChatServer::handleGetOnlineUsers(const crow::request& req) {
    crow::response res;
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Content-Type", "application/json");

    try {
        auto users = db->getOnlineUsers();
        
        crow::json::wvalue response;
        response["users"] = crow::json::wvalue::list();
        
        for (size_t i = 0; i < users.size(); ++i) {
            crow::json::wvalue user_json;
            user_json["id"] = users[i].id;
            user_json["username"] = users[i].username;
            user_json["status"] = users[i].status;
            response["users"][i] = std::move(user_json);
        }

        res.code = 200;
        res.body = response.dump();
    } catch (const std::exception& e) {
        res.code = 500;
        res.body = R"({"error":"Internal server error"})";
    }

    return res;
}

crow::response ChatServer::handleGetMessages(const crow::request& req) {
    crow::response res;
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Content-Type", "application/json");

    try {
        // 验证token
        std::string auth_header = req.get_header_value("Authorization");
        if (auth_header.substr(0, 7) != "Bearer ") {
            res.code = 401;
            res.body = R"({"error":"Unauthorized"})";
            return res;
        }

        std::string token = auth_header.substr(7);
        int user_id = validateToken(token);
        
        if (user_id <= 0) {
            res.code = 401;
            res.body = R"({"error":"Invalid token"})";
            return res;
        }

        auto messages = db->getRecentMessages(100); // 获取最近100条消息
        
        crow::json::wvalue response;
        response["messages"] = crow::json::wvalue::list();
        
        for (size_t i = 0; i < messages.size(); ++i) {
            crow::json::wvalue msg_json;
            msg_json["id"] = messages[i].id;
            msg_json["sender_id"] = messages[i].sender_id;
            msg_json["sender_name"] = messages[i].sender_name;
            msg_json["content"] = messages[i].content;
            msg_json["timestamp"] = static_cast<int64_t>(messages[i].timestamp);
            msg_json["type"] = messages[i].type;
            response["messages"][i] = std::move(msg_json);
        }

        res.code = 200;
        res.body = response.dump();
    } catch (const std::exception& e) {
        res.code = 500;
        res.body = R"({"error":"Internal server error"})";
    }

    return res;
}

void ChatServer::handleMessage(crow::websocket::connection* conn, const std::string& data) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(conn);
    if (it == clients.end()) {
        return;
    }

    auto client = it->second;
    client->last_activity = std::chrono::system_clock::now();

    try {
        auto json_data = crow::json::load(data);
        if (!json_data) {
            return;
        }

        std::string type = json_data["type"].s();
        
        if (type == "auth") {
            handleAuth(conn, json_data);
        } else if (client->user_id > 0) {
            // 用户已认证
            if (type == "message") {
                handleChatMessage(conn, json_data);
            } else if (type == "private_message") {
                handlePrivateMessage(conn, json_data);
            } else if (type == "status_change") {
                handleStatusChange(conn, json_data);
            } else if (type == "typing") {
                handleTyping(conn, json_data);
            } else if (type == "revoke_message") {
                handleRevokeMessage(conn, json_data);
            }
        }
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Error handling message: " << e.what();
    }
}

void ChatServer::handleAuth(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    std::string token = data["token"].s();
    int user_id = validateToken(token);
    
    if (user_id > 0) {
        auto client = clients[conn];
        client->user_id = user_id;
        
        User user = db->getUserById(user_id);
        client->username = user.username;
        
        // 更新用户状态为在线
        db->updateUserStatus(user_id, "online");
        
        // 发送认证成功消息
        crow::json::wvalue response;
        response["type"] = "auth_success";
        response["user"]["id"] = user.id;
        response["user"]["username"] = user.username;
        response["user"]["status"] = "online";
        
        conn->send_text(response.dump());
        
        // 广播用户上线
        broadcastUserJoined(user);
        
        // 发送在线用户列表
        sendOnlineUsers(conn);
    } else {
        crow::json::wvalue error;
        error["type"] = "auth_error";
        error["message"] = "Invalid token";
        conn->send_text(error.dump());
        conn->close();
    }
}

void ChatServer::handleChatMessage(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    auto client = clients[conn];
    std::string content = data["content"].s();
    
    // 过滤敏感词
    std::string filtered_content = filterSensitiveWords(content);
    
    // 保存消息到数据库
    Message message;
    message.sender_id = client->user_id;
    message.sender_name = client->username;
    message.content = filtered_content;
    message.type = "text";
    message.timestamp = std::time(nullptr);
    
    if (db->saveMessage(message)) {
        // 广播消息
        crow::json::wvalue broadcast;
        broadcast["type"] = "message";
        broadcast["data"]["id"] = message.id;
        broadcast["data"]["sender_id"] = message.sender_id;
        broadcast["data"]["sender_name"] = message.sender_name;
        broadcast["data"]["content"] = message.content;
        broadcast["data"]["timestamp"] = static_cast<int64_t>(message.timestamp);
        broadcast["data"]["type"] = message.type;
        
        broadcastToAll(broadcast.dump());
    }
}

void ChatServer::handlePrivateMessage(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    auto client = clients[conn];
    std::string content = data["content"].s();
    int target_user_id = data["target_user_id"].i();
    
    // 过滤敏感词
    std::string filtered_content = filterSensitiveWords(content);
    
    // 保存私聊消息
    Message message;
    message.sender_id = client->user_id;
    message.sender_name = client->username;
    message.content = filtered_content;
    message.type = "private";
    message.target_user_id = target_user_id;
    message.timestamp = std::time(nullptr);
    
    if (db->saveMessage(message)) {
        crow::json::wvalue msg_json;
        msg_json["type"] = "private_message";
        msg_json["data"]["id"] = message.id;
        msg_json["data"]["sender_id"] = message.sender_id;
        msg_json["data"]["sender_name"] = message.sender_name;
        msg_json["data"]["content"] = message.content;
        msg_json["data"]["timestamp"] = static_cast<int64_t>(message.timestamp);
        msg_json["data"]["target_user_id"] = target_user_id;
        
        // 发送给目标用户
        sendToUser(target_user_id, msg_json.dump());
        
        // 也发送给发送者确认
        conn->send_text(msg_json.dump());
    }
}

void ChatServer::handleStatusChange(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    auto client = clients[conn];
    std::string new_status = data["status"].s();
    
    if (new_status == "online" || new_status == "busy" || new_status == "offline") {
        db->updateUserStatus(client->user_id, new_status);
        
        // 广播状态变化
        crow::json::wvalue broadcast;
        broadcast["type"] = "status_change";
        broadcast["data"]["user_id"] = client->user_id;
        broadcast["data"]["status"] = new_status;
        
        broadcastToAll(broadcast.dump());
    }
}

void ChatServer::handleTyping(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    auto client = clients[conn];
    bool is_typing = data["is_typing"].b();
    
    crow::json::wvalue broadcast;
    broadcast["type"] = "typing";
    broadcast["data"]["user_id"] = client->user_id;
    broadcast["data"]["username"] = client->username;
    broadcast["data"]["is_typing"] = is_typing;
    
    broadcastToOthers(broadcast.dump(), client->user_id);
}

void ChatServer::handleRevokeMessage(crow::websocket::connection* conn, const crow::json::rvalue& data) {
    auto client = clients[conn];
    int message_id = data["message_id"].i();
    
    // 检查消息是否存在且属于该用户
    Message message = db->getMessageById(message_id);
    if (message.id == 0 || message.sender_id != client->user_id) {
        conn->send_text(R"({"type":"error","message":"Message not found or not yours"})");
        return;
    }
    
    // 检查是否在2分钟内
    auto now = std::time(nullptr);
    if (now - message.timestamp > 120) { // 2分钟
        conn->send_text(R"({"type":"error","message":"Cannot delete message (time expired)"})");
        return;
    }
    
    if (db->deleteMessage(message_id)) {
        crow::json::wvalue broadcast;
        broadcast["type"] = "message_revoked";
        broadcast["data"]["message_id"] = message_id;
        
        broadcastToAll(broadcast.dump());
    }
}

void ChatServer::handleDisconnect(crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = clients.find(conn);
    if (it != clients.end()) {
        auto client = it->second;
        if (client->user_id > 0) {
            // 更新用户状态为离线
            db->updateUserStatus(client->user_id, "offline");
            
            // 广播用户离线
            crow::json::wvalue broadcast;
            broadcast["type"] = "user_left";
            broadcast["data"]["user_id"] = client->user_id;
            broadcast["data"]["username"] = client->username;
            
            broadcastToOthers(broadcast.dump(), client->user_id);
        }
        clients.erase(it);
    }
}

std::string ChatServer::hashPassword(const std::string& password) {
    // 简单的哈希实现（实际项目中应使用更安全的方法如bcrypt）
    std::hash<std::string> hasher;
    auto hashed = hasher(password + "salt");
    return std::to_string(hashed);
}

bool ChatServer::verifyPassword(const std::string& password, const std::string& hash) {
    return hashPassword(password) == hash;
}

std::string ChatServer::generateToken(int user_id) {
    // 简单的token生成（实际项目中应使用JWT）
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return std::to_string(user_id) + "_" + std::to_string(timestamp);
}

int ChatServer::validateToken(const std::string& token) {
    // 简单的token验证
    auto pos = token.find('_');
    if (pos != std::string::npos) {
        try {
            int user_id = std::stoi(token.substr(0, pos));
            // 验证用户是否存在
            User user = db->getUserById(user_id);
            return (user.id > 0) ? user_id : 0;
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

void ChatServer::loadSensitiveWords() {
    sensitive_words = {
        "spam", "abuse", "hate", "inappropriate",
        // 添加更多敏感词
    };
}

std::string ChatServer::filterSensitiveWords(const std::string& content) {
    std::string filtered = content;
    for (const auto& word : sensitive_words) {
        std::regex word_regex(word, std::regex_constants::icase);
        filtered = std::regex_replace(filtered, word_regex, "***");
    }
    return filtered;
}

void ChatServer::broadcastToAll(const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& client_pair : clients) {
        if (client_pair.second->user_id > 0) {
            client_pair.first->send_text(message);
        }
    }
}

void ChatServer::broadcastToOthers(const std::string& message, int exclude_user_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& client_pair : clients) {
        if (client_pair.second->user_id > 0 && client_pair.second->user_id != exclude_user_id) {
            client_pair.first->send_text(message);
        }
    }
}

void ChatServer::sendToUser(int user_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& client_pair : clients) {
        if (client_pair.second->user_id == user_id) {
            client_pair.first->send_text(message);
            break;
        }
    }
}

void ChatServer::broadcastUserJoined(const User& user) {
    crow::json::wvalue broadcast;
    broadcast["type"] = "user_joined";
    broadcast["data"]["id"] = user.id;
    broadcast["data"]["username"] = user.username;
    broadcast["data"]["status"] = user.status;
    
    broadcastToOthers(broadcast.dump(), user.id);
}

void ChatServer::sendOnlineUsers(crow::websocket::connection* conn) {
    auto users = db->getOnlineUsers();
    
    crow::json::wvalue response;
    response["type"] = "user_list";
    response["data"] = crow::json::wvalue::list();
    
    for (size_t i = 0; i < users.size(); ++i) {
        crow::json::wvalue user_json;
        user_json["id"] = users[i].id;
        user_json["username"] = users[i].username;
        user_json["status"] = users[i].status;
        response["data"][i] = std::move(user_json);
    }
    
    conn->send_text(response.dump());
}

void ChatServer::removeUserConnections(int user_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto it = clients.begin(); it != clients.end();) {
        if (it->second->user_id == user_id) {
            it = clients.erase(it);
        } else {
            ++it;
        }
    }
}

void ChatServer::run(int port) {
    std::cout << "启动聊天服务器在端口 " << port << std::endl;
    app.port(port).multithreaded().run();
}
