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
            avatar_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    const char* create_messages_table = R"(
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER DEFAULT 0,
            content TEXT NOT NULL,
            message_type TEXT DEFAULT 'public',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_deleted BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
    )";
    
    const char* create_blocked_users_table = R"(
        CREATE TABLE IF NOT EXISTS blocked_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            blocked_user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (blocked_user_id) REFERENCES users(id),
            UNIQUE(user_id, blocked_user_id)
        );
    )";
    
    const char* create_sensitive_words_table = R"(
        CREATE TABLE IF NOT EXISTS sensitive_words (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            word TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    const char* create_message_reads_table = R"(
        CREATE TABLE IF NOT EXISTS message_reads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(message_id, user_id)
        );
    )";
    
    return executeQuery(create_users_table) &&
           executeQuery(create_messages_table) &&
           executeQuery(create_blocked_users_table) &&
           executeQuery(create_sensitive_words_table) &&
           executeQuery(create_message_reads_table);
}

bool Database::executeQuery(const std::string& query) {
    char* error_msg = nullptr;
    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &error_msg);
    
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << error_msg << std::endl;
        sqlite3_free(error_msg);
        return false;
    }
    
    return true;
}

bool Database::createUser(const std::string& username, const std::string& password_hash, 
                         const std::string& email) {
    const char* sql = R"(
        INSERT INTO users (username, password_hash, email) 
        VALUES (?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, email.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

User* Database::authenticateUser(const std::string& username, const std::string& password_hash) {
    const char* sql = R"(
        SELECT id, username, password_hash, email, status, avatar_url, created_at, last_login
        FROM users WHERE username = ? AND password_hash = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    
    User* user = nullptr;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user = new User();
        user->id = sqlite3_column_int(stmt, 0);
        user->username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user->password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user->email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user->status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (sqlite3_column_text(stmt, 5)) {
            user->avatar_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        }
    }
    
    sqlite3_finalize(stmt);
    return user;
}

bool Database::updateUserStatus(int user_id, const std::string& status) {
    const char* sql = R"(
        UPDATE users SET status = ?, last_login = CURRENT_TIMESTAMP 
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::vector<User> Database::getOnlineUsers() {
    const char* sql = R"(
        SELECT id, username, email, status, avatar_url, created_at, last_login
        FROM users WHERE status IN ('online', 'busy')
        ORDER BY last_login DESC;
    )";
    
    sqlite3_stmt* stmt;
    std::vector<User> users;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return users;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (sqlite3_column_text(stmt, 4)) {
            user.avatar_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        }
        users.push_back(user);
    }
    
    sqlite3_finalize(stmt);
    return users;
}

User* Database::getUserById(int user_id) {
    const char* sql = R"(
        SELECT id, username, password_hash, email, status, avatar_url, created_at, last_login
        FROM users WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return nullptr;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    User* user = nullptr;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user = new User();
        user->id = sqlite3_column_int(stmt, 0);
        user->username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user->password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user->email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user->status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (sqlite3_column_text(stmt, 5)) {
            user->avatar_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        }
    }
    
    sqlite3_finalize(stmt);
    return user;
}

User* Database::getUserByUsername(const std::string& username) {
    const char* sql = R"(
        SELECT id, username, password_hash, email, status, avatar_url, created_at, last_login
        FROM users WHERE username = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return nullptr;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    User* user = nullptr;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user = new User();
        user->id = sqlite3_column_int(stmt, 0);
        user->username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user->password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user->email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user->status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (sqlite3_column_text(stmt, 5)) {
            user->avatar_url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        }
    }
    
    sqlite3_finalize(stmt);
    return user;
}

bool Database::saveMessage(int sender_id, int receiver_id, const std::string& content,
                          const std::string& message_type) {
    const char* sql = R"(
        INSERT INTO messages (sender_id, receiver_id, content, message_type) 
        VALUES (?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, content.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, message_type.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::vector<Message> Database::getRecentMessages(int limit) {
    const char* sql = R"(
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.message_type, 
               m.timestamp, m.is_deleted, u.username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.message_type = 'public' AND m.is_deleted = 0
        AND m.timestamp >= datetime('now', '-3 days')
        ORDER BY m.timestamp DESC
        LIMIT ?;
    )";
    
    sqlite3_stmt* stmt;
    std::vector<Message> messages;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return messages;
    }
    
    sqlite3_bind_int(stmt, 1, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Message msg;
        msg.id = sqlite3_column_int(stmt, 0);
        msg.sender_id = sqlite3_column_int(stmt, 1);
        msg.receiver_id = sqlite3_column_int(stmt, 2);
        msg.content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        msg.message_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        msg.is_deleted = sqlite3_column_int(stmt, 6) != 0;
        msg.sender_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        messages.push_back(msg);
    }
    
    sqlite3_finalize(stmt);
    return messages;
}

std::vector<Message> Database::getPrivateMessages(int user1_id, int user2_id, int limit) {
    const char* sql = R"(
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.message_type, 
               m.timestamp, m.is_deleted, u.username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.message_type = 'private' AND m.is_deleted = 0
        AND ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        AND m.timestamp >= datetime('now', '-3 days')
        ORDER BY m.timestamp DESC
        LIMIT ?;
    )";
    
    sqlite3_stmt* stmt;
    std::vector<Message> messages;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return messages;
    }
    
    sqlite3_bind_int(stmt, 1, user1_id);
    sqlite3_bind_int(stmt, 2, user2_id);
    sqlite3_bind_int(stmt, 3, user2_id);
    sqlite3_bind_int(stmt, 4, user1_id);
    sqlite3_bind_int(stmt, 5, limit);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Message msg;
        msg.id = sqlite3_column_int(stmt, 0);
        msg.sender_id = sqlite3_column_int(stmt, 1);
        msg.receiver_id = sqlite3_column_int(stmt, 2);
        msg.content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        msg.message_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        msg.is_deleted = sqlite3_column_int(stmt, 6) != 0;
        msg.sender_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        messages.push_back(msg);
    }
    
    sqlite3_finalize(stmt);
    return messages;
}

bool Database::deleteMessage(int message_id, int user_id) {
    const char* sql = R"(
        UPDATE messages SET is_deleted = 1 
        WHERE id = ? AND sender_id = ? 
        AND datetime('now') <= datetime(timestamp, '+2 minutes');
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, message_id);
    sqlite3_bind_int(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE && sqlite3_changes(db) > 0;
}

bool Database::blockUser(int user_id, int blocked_user_id) {
    const char* sql = R"(
        INSERT OR IGNORE INTO blocked_users (user_id, blocked_user_id) 
        VALUES (?, ?);
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, blocked_user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool Database::unblockUser(int user_id, int blocked_user_id) {
    const char* sql = R"(
        DELETE FROM blocked_users 
        WHERE user_id = ? AND blocked_user_id = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, blocked_user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::vector<int> Database::getBlockedUsers(int user_id) {
    const char* sql = R"(
        SELECT blocked_user_id FROM blocked_users WHERE user_id = ?;
    )";
    
    sqlite3_stmt* stmt;
    std::vector<int> blocked_users;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return blocked_users;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        blocked_users.push_back(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return blocked_users;
}

bool Database::isUserBlocked(int user_id, int blocked_user_id) {
    const char* sql = R"(
        SELECT COUNT(*) FROM blocked_users 
        WHERE user_id = ? AND blocked_user_id = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, blocked_user_id);
    
    bool is_blocked = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        is_blocked = sqlite3_column_int(stmt, 0) > 0;
    }
    
    sqlite3_finalize(stmt);
    return is_blocked;
}

bool Database::addSensitiveWord(const std::string& word) {
    const char* sql = R"(
        INSERT OR IGNORE INTO sensitive_words (word) VALUES (?);
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, word.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::vector<std::string> Database::getSensitiveWords() {
    const char* sql = R"(
        SELECT word FROM sensitive_words ORDER BY word;
    )";
    
    sqlite3_stmt* stmt;
    std::vector<std::string> words;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return words;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        words.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }
    
    sqlite3_finalize(stmt);
    return words;
}

bool Database::removeSensitiveWord(const std::string& word) {
    const char* sql = R"(
        DELETE FROM sensitive_words WHERE word = ?;
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, word.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}
