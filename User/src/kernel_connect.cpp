#include "kernel_connect.h"

int main()
{
    std::thread(thread_send_msg_to_core).detach();
    get_msg_from_kernel();
    return 0;
}

void send_msg_to_core(REALTIME_INFO *msg)
{
    std::string cmdline, process_path;
    json write_event;

    cmdline = get_cmd_line(msg->pid);
    if (cmdline.length())
    {
        size_t pos = cmdline.find(' ');
        if (pos == std::string::npos)
            process_path = cmdline;
        else
            process_path = cmdline.substr(0, pos);
    }

    write_event["id"] = WRITE_FILE_MSG_ID;
    write_event["fp"] = msg->file_path;
    write_event["fp2"] = "";
    write_event["pid"] = msg->pid;
    write_event["pb"] = process_path;
    write_event["cmd"] = cmdline;

    std::string json_string = write_event.dump();
    std::cout << json_string << std::endl;
}

void thread_send_msg_to_core()
{
    REALTIME_INFO *msg;

    while (true)
    {
        msg = NULL;

        std::unique_lock<std::mutex> lock(g_mutex);
        g_cv.wait(lock, [] { return g_ready; });
        g_ready = false;

        g_cache_mutex.lock();
        if (!g_realtime_msg_cache.empty())
        {
            msg = g_realtime_msg_cache.front();
            g_realtime_msg_cache.pop();
            g_cache_mutex.unlock();

            if (msg)
            {
                send_msg_to_core(msg);
                delete[](msg);
            }
        }
        else g_cache_mutex.unlock();
    }
}

void get_msg_from_kernel()
{
    int fd = 0, ret;
    struct pollfd fds[1];

    fd = open(DEVICE_NAME, O_RDONLY);
    if (fd < 0)
    {
        perror("get_msg_from_kernel - Failed to open character device file");
        return;
    }

    fds[0].fd = fd;
    fds[0].events = POLLIN; 

    while (true)
    {
        ret = poll(fds, 1, POLL_TIMEOUT);
        if (ret == -1)
        {
            perror("get_msg_from_kernel - poll failed");
            break;
        }
        else if (ret == 0)
        {
            printf("get_msg_from_kernel - Timeout occurred! No data to read.\n");
        }
        else
        {
            if (fds[0].revents & POLLIN)
            {
                if (!read_msg(fd))
                {
                    perror("get_msg_from_kernel - read_msg failed");
                    break;
                }
            }
        }
    }

    close(fd);
}

bool read_msg(int fd)
{
    int len = 0;
    bool result = true;
    ssize_t bytes_read = 0;
    REALTIME_INFO *realtime_info_ptr;

    while (true)
    {
        realtime_info_ptr = new REALTIME_INFO;
        memset(realtime_info_ptr, 0, sizeof(REALTIME_INFO));
        lseek(fd, 0, SEEK_SET);

        len = read(fd, realtime_info_ptr, sizeof(REALTIME_INFO));
        if (len > 0)
        {
            //printf("read_msg - pid: %d, path: %s\n", realtime_info_ptr->pid, realtime_info_ptr->file_path);
            g_cache_mutex.lock();
            g_realtime_msg_cache.push(realtime_info_ptr);
            g_cache_mutex.unlock();

            g_ready = true;
            g_cv.notify_one();
        }
        else if (len == 0)
        {
            delete[](realtime_info_ptr);
            break;
        }
        else
        {
            result = false;
            delete[](realtime_info_ptr);
            break;
        }
    }

    return result;
}

std::string get_cmd_line(int pid)
{
    std::string cmdline_file_path, cmdline;
    std::ifstream ifstream;
    char c;

    cmdline_file_path = "/proc/" + std::to_string(pid) + "/cmdline";
    ifstream.open(cmdline_file_path, std::ifstream::in | std::ifstream::binary);

    if (ifstream.is_open() == false)
    {
        std::cout << "open file: " << cmdline_file_path << "error" << std::endl;
        return cmdline;
    }

    while (ifstream.get(c)) {
        if (c == '\0')
            cmdline += ' ';
        else
            cmdline += c;
    }

    if (cmdline.at(cmdline.length() - 1) == ' ')
        cmdline.pop_back();

    ifstream.close();
    return cmdline;
}