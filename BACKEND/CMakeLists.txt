cmake_minimum_required(VERSION 3.15)
project(ChatRoomServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖包
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# 尝试使用 pkg-config 查找 Crow，如果失败则手动查找
pkg_check_modules(CROW QUIET crow)

if(NOT CROW_FOUND)
    # Fallback: 在 Homebrew 安装位置查找 Crow
    find_path(CROW_INCLUDE_DIR 
        NAMES crow.h
        PATHS /opt/homebrew/include
              /usr/local/include
    )
    
    if(CROW_INCLUDE_DIR)
        set(CROW_INCLUDE_DIRS ${CROW_INCLUDE_DIR})
        message(STATUS "Found Crow headers: ${CROW_INCLUDE_DIR}")
    else()
        message(FATAL_ERROR "Crow headers not found!")
    endif()
endif()

# 查找 SQLite3
find_library(SQLITE3_LIBRARIES sqlite3)

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# 包含头文件目录
include_directories(${CROW_INCLUDE_DIRS})
include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

# 设置源文件
set(SOURCES
    src/main.cpp
    src/chat_server.cpp
    src/database.cpp
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接库
target_link_libraries(${PROJECT_NAME} 
    ${SQLITE3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
    pthread
)

# 如果找到了 CROW 库，则链接它
if(CROW_LIBRARIES)
    target_link_libraries(${PROJECT_NAME} ${CROW_LIBRARIES})
endif()

# 编译选项
if(CROW_CFLAGS_OTHER)
    target_compile_options(${PROJECT_NAME} PRIVATE ${CROW_CFLAGS_OTHER})
endif()

# 设置输出目录
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
