# 多用户聊天室系统 - 后端服务器

基于 Linux 的多用户聊天室系统，使用 C++ Crow 框架和 SQLite 数据库。

## 技术栈

- **后端框架**: C++ Crow (轻量级 Web 框架)
- **数据库**: SQLite3
- **通信协议**: WebSocket + REST API
- **多线程**: C++ std::thread
- **依赖管理**: Homebrew (macOS) / apt (Ubuntu)

## 功能特性

### 核心功能
- ✅ 支持 3+ 用户同时在线聊天
- ✅ 用户注册、登录、注销
- ✅ 实时消息广播
- ✅ 私聊功能
- ✅ 消息历史记录（保存 3 天）

### 权限管理
- ✅ 屏蔽特定用户消息
- ✅ 撤回自己的消息（2分钟内）
- ✅ 设置在线状态（在线/忙碌/离线）

### 高级功能
- ✅ 敏感词过滤
- ✅ 在线用户列表
- ✅ 消息已读状态
- ✅ 跨平台支持 (macOS/Linux)

## 项目结构

```
BACKEND/
├── CMakeLists.txt          # CMake 构建配置
├── build.sh               # 自动构建脚本
├── README.md              # 项目说明
├── include/               # 头文件
│   ├── database.h         # 数据库管理类
│   └── chat_server.h      # 聊天服务器类
└── src/                   # 源文件
    ├── main.cpp           # 主程序入口
    ├── database.cpp       # 数据库实现
    └── chat_server.cpp    # 服务器实现
```

## 数据库设计

### 用户表 (users)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'offline',
    avatar_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 消息表 (messages)
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER DEFAULT 0,  -- 0 表示公共消息
    content TEXT NOT NULL,
    message_type TEXT DEFAULT 'public',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);
```

### 屏蔽用户表 (blocked_users)
```sql
CREATE TABLE blocked_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    blocked_user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (blocked_user_id) REFERENCES users(id),
    UNIQUE(user_id, blocked_user_id)
);
```

### 敏感词表 (sensitive_words)
```sql
CREATE TABLE sensitive_words (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 消息已读表 (message_reads)
```sql
CREATE TABLE message_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(message_id, user_id)
);
```

## WebSocket 消息协议

### 客户端发送消息格式

#### 登录
```json
{
    "type": "login",
    "username": "用户名",
    "password_hash": "密码哈希"
}
```

#### 发送公共消息
```json
{
    "type": "send_message",
    "content": "消息内容"
}
```

#### 发送私聊消息
```json
{
    "type": "private_message",
    "receiver_id": 123,
    "content": "私聊内容"
}
```

#### 删除消息
```json
{
    "type": "delete_message",
    "message_id": 456
}
```

#### 屏蔽用户
```json
{
    "type": "block_user",
    "blocked_user_id": 789
}
```

#### 设置状态
```json
{
    "type": "status_change",
    "status": "online|busy|offline"
}
```

### 服务器推送消息格式

#### 新消息广播
```json
{
    "type": "new_message",
    "sender_id": 123,
    "sender_username": "发送者",
    "content": "消息内容",
    "message_type": "public",
    "timestamp": "2024-01-01T12:00:00Z"
}
```

#### 在线用户列表
```json
{
    "type": "online_users",
    "users": [
        {
            "id": 123,
            "username": "用户1",
            "status": "online",
            "avatar_url": ""
        }
    ]
}
```

## REST API 接口

### 用户注册
- **POST** `/api/register`
- **Body**: `{"username": "用户名", "password": "密码", "email": "邮箱"}`

### 用户登录
- **POST** `/api/login`
- **Body**: `{"username": "用户名", "password": "密码"}`

### 获取消息历史
- **GET** `/api/messages`

### 获取在线用户
- **GET** `/api/users`

## 编译和运行

### 在 macOS 上

1. **安装依赖**
```bash
# 安装 Homebrew (如果没有)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装依赖
brew install crow sqlite3 cmake pkg-config jsoncpp openssl
```

2. **编译项目**
```bash
# 使用自动构建脚本
./build.sh

# 或手动编译
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

3. **运行服务器**
```bash
cd build/bin
./ChatRoomServer [端口号]  # 默认端口 8080
```

### 在 Ubuntu 上

1. **安装依赖**
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libsqlite3-dev libssl-dev libjsoncpp-dev

# 安装 Crow 框架
git clone https://github.com/CrowCpp/Crow.git
cd Crow
mkdir build && cd build
cmake .. -DCROW_BUILD_EXAMPLES=OFF
make -j$(nproc)
sudo make install
```

2. **编译和运行** (同 macOS)

## 使用示例

1. **启动服务器**
```bash
./ChatRoomServer 8080
```

2. **连接测试**
- WebSocket: `ws://localhost:8080/ws`
- 网页测试: `http://localhost:8080`

3. **注册用户**
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"123456","email":"test@example.com"}'
```

## 多线程设计

- **主线程**: HTTP/WebSocket 服务器
- **工作线程**: 消息处理和数据库操作
- **线程安全**: 使用 `std::mutex` 保护共享资源
- **连接管理**: 智能指针管理客户端连接

## 安全特性

- 密码哈希存储
- SQL 注入防护 (参数化查询)
- 敏感词过滤
- 用户屏蔽机制
- 消息时效控制

## 性能优化

- 连接池管理
- 消息批量处理
- 数据库索引优化
- 内存缓存机制

## 故障排除

### 常见问题

1. **编译错误**: 确保所有依赖已正确安装
2. **端口占用**: 更改端口或杀死占用进程
3. **数据库权限**: 确保有写入权限
4. **WebSocket 连接失败**: 检查防火墙设置

### 日志查看

服务器运行时会输出详细日志，包括：
- 用户连接/断开
- 消息发送/接收
- 错误信息

## 扩展功能

未来可以添加的功能：
- 文件传输
- 语音/视频通话
- 表情包支持
- 群组管理
- 消息加密
- 负载均衡

## 许可证

MIT License
