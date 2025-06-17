#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>
#include <vector>
#include <memory>
#include <chrono>

struct User {
    int id;
    std::string username;
    std::string password_hash;
    std::string email;
    std::string status; // online, busy, offline
    std::string avatar_url;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login;
};

struct Message {
    int id;
    int sender_id;
    int receiver_id; // 0 for public messages
    std::string content;
    std::string message_type; // public, private
    std::chrono::system_clock::time_point timestamp;
    bool is_deleted;
    std::string sender_username;
};

struct BlockedUser {
    int user_id;
    int blocked_user_id;
};

class Database {
private:
    sqlite3* db;
    std::string db_path;

public:
    Database(const std::string& path);
    ~Database();
    
    bool init();
    void close();
    
    // 用户管理
    int createUser(const std::string& username, const std::string& email, const std::string& password_hash);
    bool userExists(const std::string& username);
    std::pair<int, std::string> authenticateUser(const std::string& username, const std::string& password_hash);
    std::pair<int, std::string> getUserInfo(int user_id);
    bool updateUserStatus(int user_id, const std::string& status);
    std::vector<User> getOnlineUsers();
    User* getUserById(int user_id);
    User* getUserByUsername(const std::string& username);
    
    // 消息管理
    int saveMessage(int sender_id, const std::string& sender_name, const std::string& content, const std::string& message_type);
    int savePrivateMessage(int sender_id, int receiver_id, const std::string& sender_name, const std::string& content);
    std::vector<Message> getRecentMessages(int days = 3);
    std::vector<Message> getPrivateMessages(int user1_id, int user2_id, int limit = 50);
    bool deleteMessage(int message_id);
    bool canRevokeMessage(int message_id, int user_id);
    std::vector<Message> getMessagesInTimeRange(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end);
    
    // 用户屏蔽管理
    bool blockUser(int user_id, int blocked_user_id);
    bool unblockUser(int user_id, int blocked_user_id);
    std::vector<int> getBlockedUsers(int user_id);
    bool isUserBlocked(int user_id, int blocked_user_id);
    
    // 敏感词管理
    bool addSensitiveWord(const std::string& word);
    std::vector<std::string> getSensitiveWords();
    bool removeSensitiveWord(const std::string& word);
    
private:
    bool executeQuery(const std::string& query);
    bool createTables();
};

#endif // DATABASE_H
