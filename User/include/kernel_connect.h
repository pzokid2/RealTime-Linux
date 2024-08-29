#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define DEVICE_NAME                     "/dev/daolv@1999"
#define POLL_TIMEOUT                    -1
#define PATH_MAX                        4096
#define WRITE_FILE_MSG_ID				4

struct REALTIME_INFO
{
	int pid;
	char file_path[PATH_MAX];
};

void get_msg_from_kernel();
bool read_msg(int);
void thread_send_msg_to_core();
void send_msg_to_core(REALTIME_INFO *msg);
std::string get_cmd_line(int pid);

static std::queue<REALTIME_INFO *> g_realtime_msg_cache;
static std::mutex g_cache_mutex;
static std::mutex g_mutex;
static std::condition_variable g_cv;
bool g_ready = false;