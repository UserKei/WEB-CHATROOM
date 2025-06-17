#include "database.h"
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>

Database::Database(const std::string& path) : db(nullptr), db_path(path) {}

Database::~Database() {
    close();
}

bool Database::init() {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    return createTables();
}

void Database::close() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool Database::createTables() {
    const char* create_users_table = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'offline',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    const char* create_messages_table = R"(
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER DEFAULT 0,
            sender_name TEXT NOT NULL,
            content TEXT NOT NULL,
            message_type TEXT DEFAULT 'public',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_deleted BOOLEAN DEFAULT 0
        );
    )";
    
    const char* create_blocked_users_table = R"(
        CREATE TABLE IF NOT EXISTS blocked_users (
            user_id INTEGER NOT NULL,
            blocked_user_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, blocked_user_id)
        );
    )";
    
    if (sqlite3_exec(db, create_users_table, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error creating users table: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    if (sqlite3_exec(db, create_messages_table, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error creating messages table: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    if (sqlite3_exec(db, create_blocked_users_table, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error creating blocked_users table: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    return true;
}

int Database::createUser(const std::string& username, const std::string& email, const std::string& password_hash) {
    const char* sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, password_hash.c_str(), -1, SQLITE_STATIC);
    
    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db);
    } else {
        std::cerr << "Error creating user: " << sqlite3_errmsg(db) << std::endl;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool Database::userExists(const std::string& username) {
    const char* sql = "SELECT COUNT(*) FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }
    
    sqlite3_finalize(stmt);
    return exists;
}

std::pair<int, std::string> Database::authenticateUser(const std::string& username, const std::string& password_hash) {
    const char* sql = "SELECT id, email FROM users WHERE username = ? AND password_hash = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return {0, ""};
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    
    std::pair<int, std::string> result = {0, ""};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result.first = sqlite3_column_int(stmt, 0);
        result.second = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::pair<int, std::string> Database::getUserInfo(int user_id) {
    const char* sql = "SELECT id, username FROM users WHERE id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return {0, ""};
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    std::pair<int, std::string> result = {0, ""};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result.first = sqlite3_column_int(stmt, 0);
        result.second = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool Database::updateUserStatus(int user_id, const std::string& status) {
    const char* sql = "UPDATE users SET status = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user_id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<User> Database::getOnlineUsers() {
    std::vector<User> users;
    const char* sql = "SELECT id, username, status FROM users WHERE status != 'offline'";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return users;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        users.push_back(user);
    }
    
    sqlite3_finalize(stmt);
    return users;
}

int Database::saveMessage(int sender_id, const std::string& sender_name, const std::string& content, const std::string& message_type) {
    const char* sql = "INSERT INTO messages (sender_id, sender_name, content, message_type) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_text(stmt, 2, sender_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, content.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, message_type.c_str(), -1, SQLITE_STATIC);
    
    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

int Database::savePrivateMessage(int sender_id, int receiver_id, const std::string& sender_name, const std::string& content) {
    const char* sql = "INSERT INTO messages (sender_id, receiver_id, sender_name, content, message_type) VALUES (?, ?, ?, ?, 'private')";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, sender_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, content.c_str(), -1, SQLITE_STATIC);
    
    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Message> Database::getRecentMessages(int days) {
    std::vector<Message> messages;
    const char* sql = "SELECT id, sender_id, receiver_id, sender_name, content, message_type, timestamp FROM messages WHERE message_type = 'text' AND timestamp >= datetime('now', '-' || ? || ' days') AND is_deleted = 0 ORDER BY timestamp DESC LIMIT 100";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return messages;
    }
    
    sqlite3_bind_int(stmt, 1, days);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Message msg;
        msg.id = sqlite3_column_int(stmt, 0);
        msg.sender_id = sqlite3_column_int(stmt, 1);
        msg.receiver_id = sqlite3_column_int(stmt, 2);
        msg.sender_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        msg.content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        msg.message_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        // Note: timestamp parsing would need proper implementation
        msg.is_deleted = false;
        messages.push_back(msg);
    }
    
    sqlite3_finalize(stmt);
    return messages;
}

bool Database::deleteMessage(int message_id) {
    const char* sql = "UPDATE messages SET is_deleted = 1 WHERE id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, message_id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::canRevokeMessage(int message_id, int user_id) {
    const char* sql = "SELECT COUNT(*) FROM messages WHERE id = ? AND sender_id = ? AND timestamp >= datetime('now', '-2 minutes')";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, message_id);
    sqlite3_bind_int(stmt, 2, user_id);
    
    bool canRevoke = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        canRevoke = sqlite3_column_int(stmt, 0) > 0;
    }
    
    sqlite3_finalize(stmt);
    return canRevoke;
}

bool Database::blockUser(int user_id, int blocked_user_id) {
    const char* sql = "INSERT OR IGNORE INTO blocked_users (user_id, blocked_user_id) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, blocked_user_id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// 为了保持兼容性，保留旧方法但标记为未使用
User* Database::getUserById(int user_id) { return nullptr; }
User* Database::getUserByUsername(const std::string& username) { return nullptr; }
std::vector<Message> Database::getPrivateMessages(int user1_id, int user2_id, int limit) { return {}; }
std::vector<Message> Database::getMessagesInTimeRange(const std::chrono::system_clock::time_point& start, const std::chrono::system_clock::time_point& end) { return {}; }
bool Database::unblockUser(int user_id, int blocked_user_id) { return false; }
std::vector<int> Database::getBlockedUsers(int user_id) { return {}; }
bool Database::isUserBlocked(int user_id, int blocked_user_id) { return false; }
bool Database::addSensitiveWord(const std::string& word) { return false; }
std::vector<std::string> Database::getSensitiveWords() { return {}; }
bool Database::removeSensitiveWord(const std::string& word) { return false; }
bool Database::executeQuery(const std::string& query) { return false; }
