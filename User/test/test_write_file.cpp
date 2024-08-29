#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    // Đường dẫn tới file
    const char* path = "/home/luongviet/Downloads/daolv.txt";

    // Nội dung cần ghi vào file
    const char* content = "Hello, this is a test!\n";

    // Mở file với cờ O_WRONLY để chỉ ghi, O_CREAT để tạo file nếu chưa tồn tại, O_TRUNC để xóa nội dung cũ
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd == -1) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }

    sleep(3);
    // Ghi nội dung vào file
    ssize_t bytes_written = write(fd, content, strlen(content));

    if (bytes_written == -1) {
        std::cerr << "Failed to write to file" << std::endl;
        close(fd);
        return 1;
    }

    std::cout << "Successfully written to file" << std::endl;

    // Đóng file
    close(fd);

    while (true)
    {
        sleep(5);
    }

    return 0;
}
