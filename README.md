# 多用户聊天室系统

这是一个基于 Linux 的多用户聊天室系统，是操作系统课设项目。

## 技术栈

### 后端
- **C++ Crow框架** - 高性能 Web 框架
- **SQLite** - 轻量级数据库
- **WebSocket** - 实时通信
- **OpenSSL** - 密码加密
- **nlohmann/json** - JSON 处理

### 前端
- **Vue 3** - 现代化前端框架
- **Tailwind CSS** - 原子化 CSS 框架
- **Motion for Vue** - 动画库
- **Heroicons** - 图标库
- **Pinia** - 状态管理
- **Axios** - HTTP 客户端

## 功能特性

### 核心功能
1. **多用户同时在线聊天** - 支持 3+ 用户同时聊天
2. **用户认证系统** - 注册、登录、注销
3. **权限管理**：
   - 屏蔽特定用户消息
   - 撤回自己发送的消息（2分钟内）
   - 设置在线状态（在线/忙碌/离线）

### 消息管理
4. **消息存储** - 保存最近3天的聊天记录
5. **历史消息** - 支持查看历史消息
6. **敏感词过滤** - 自动过滤不当内容

### 扩展功能
7. **在线用户列表** - 实时显示在线用户
8. **私聊功能** - 一对一私密聊天
9. **消息已读状态** - 显示消息读取状态
10. **实时打字提示** - 显示正在输入状态

## 系统架构

### 前后端分离
```
Frontend (Vue3 + Tailwind)  ←→  Backend (C++ Crow)
         ↑                              ↑
    WebSocket连接                  SQLite数据库
```

### API 设计

#### RESTful API
- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/logout` - 用户登出
- `GET /api/messages` - 获取消息历史
- `GET /api/users` - 获取在线用户列表

#### WebSocket 消息协议
```json
{
  "type": "message|private_message|status_change|typing|...",
  "data": { ... },
  "timestamp": "2025-06-17T05:00:32.123Z"
}
```

### 数据库表结构

#### 用户表 (users)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'offline',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### 消息表 (messages)
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER DEFAULT 0,
    sender_name TEXT NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT DEFAULT 'public',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT 0
);
```

#### 屏蔽用户表 (blocked_users)
```sql
CREATE TABLE blocked_users (
    user_id INTEGER NOT NULL,
    blocked_user_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, blocked_user_id)
);
```

## 启动指南

### 后端启动
```bash
cd BACKEND
./build.sh        # 构建项目
cd build/bin
./ChatRoomServer   # 启动服务器 (默认端口8080)
```

### 前端启动
```bash
cd FRONTEND
npm install        # 安装依赖
npm run dev       # 启动开发服务器 (默认端口5173)
```

### 访问地址
- **前端界面**: http://localhost:5173
- **后端API**: http://localhost:8080/api
- **WebSocket**: ws://localhost:8080/ws

## 设计风格

### UI/UX 设计
- **Apple 美术设计风格** - 简洁、现代、优雅
- **Telegram UI 参考** - 用户友好的聊天界面
- **玻璃拟态效果** - 现代化的视觉体验
- **流畅动画** - Motion for Vue 提供的动画效果

### 色彩方案
- **主色调**: Apple Blue (#007AFF)
- **Telegram Blue**: (#2AABEE)
- **状态颜色**: 在线(绿色)、忙碌(黄色)、离线(灰色)

## C/C++ 多线程特性

### 线程安全
- 使用 `std::mutex` 保护共享资源
- WebSocket 连接管理的线程安全
- 数据库操作的并发控制

### 多线程架构
```cpp
// 客户端连接管理
std::unordered_map<crow::websocket::connection*, std::shared_ptr<ClientConnection>> clients;
std::mutex clients_mutex;

// 线程安全的广播
void broadcastToAll(const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    // 安全地遍历所有连接
}
```

## 部署到 Ubuntu

### 依赖安装
```bash
# Ubuntu 系统依赖
sudo apt update
sudo apt install -y build-essential cmake libsqlite3-dev libssl-dev pkg-config

# 安装 Crow 框架
git clone https://github.com/CrowCpp/Crow.git
cd Crow && mkdir build && cd build
cmake .. && make -j4 && sudo make install

# 安装 nlohmann/json
sudo apt install -y nlohmann-json3-dev
```

### 构建和运行
```bash
# 构建后端
cd BACKEND && mkdir build && cd build
cmake .. && make

# 运行服务器
./ChatRoomServer 8080
```

## 项目特色

1. **现代化技术栈** - 使用最新的 C++、Vue3 技术
2. **美观界面** - Apple + Telegram 设计风格
3. **实时通信** - WebSocket 双向通信
4. **线程安全** - 多线程并发处理
5. **可扩展性** - 模块化设计，易于扩展
6. **跨平台** - 支持 macOS、Linux 部署

## 开发说明

该项目展示了现代 C++ 网络编程、前端开发、实时通信、数据库设计等多个技术领域的综合应用，是一个完整的全栈聊天室解决方案。
