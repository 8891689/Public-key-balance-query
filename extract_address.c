//  gcc extract_address.c -O3 -march=native -o extract_address
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <ctype.h> 


#define MAX_LINE_LENGTH 2048

int main(int argc, char *argv[]) {
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    char line_buffer[MAX_LINE_LENGTH]; // 用于存储从文件读取的每一行数据

    // 1. 检查命令行参数数量
    // 程序名 + 输入文件路径 + 输出文件路径 = 3个参数
    if (argc != 3) {
        // 如果参数数量不对，打印用法提示到标准错误流并退出
        fprintf(stderr, "用法: %s <输入文件路径> <输出文件路径>\n", argv[0]);
        return EXIT_FAILURE; // 返回一个非零值表示程序因错误退出
    }

    // 2. 获取输入文件和输出文件路径
    const char *input_filename = argv[1];
    const char *output_filename = argv[2];

    // 3. 打开输入文件 (只读模式)
    input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
        // 如果文件打开失败，打印错误信息并退出
        perror("错误：无法打开输入文件"); // perror 会打印系统错误信息（如 File not found）
        return EXIT_FAILURE;
    }

    // 4. 打开输出文件 (写入模式)
    output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
        // 如果文件打开失败，打印错误信息
        perror("错误：无法打开输出文件");
        // 重要：确保在退出前关闭已成功打开的文件
        fclose(input_file);
        return EXIT_FAILURE;
    }

    // 5. 逐行读取输入文件并处理
    // fgets 从输入流读取最多 size-1 个字符，或直到遇到换行符或文件末尾
    while (fgets(line_buffer, sizeof(line_buffer), input_file) != NULL) {
        // 获取当前行的实际读取长度
        size_t len = strlen(line_buffer);

        // 6. 移除行尾的换行符 (\n) 或回车符 (\r)
        // fgets 会读取换行符，但我们通常不希望它出现在提取的地址中。
        // 兼容不同系统：Windows 使用 \r\n，Unix/Linux 使用 \n。
        if (len > 0 && (line_buffer[len - 1] == '\n' || line_buffer[len - 1] == '\r')) {
            line_buffer[len - 1] = '\0'; // 用字符串结束符替换换行符
            // 检查是否是 Windows 的 \r\n 组合，如果是，也替换掉 \r
            if (len > 1 && line_buffer[len - 2] == '\r') {
                line_buffer[len - 2] = '\0';
            }
        }

        // 7. 跳过移除换行符后变为空的行 (对应 Python 中的 if not line:)
        if (strlen(line_buffer) == 0) {
            continue; // 跳过当前循环的剩余部分，处理下一行
        }

        // 8. 查找第一个制表符 (\t) 的位置
        char *tab_ptr = strchr(line_buffer, '\t');

        // 9. 提取地址部分 (即第一个字段)
        // Python 的 line.split("\t")[0] 行为：
        // - 如果找到制表符，取其之前的部分。
        // - 如果没找到制表符，取整个字符串。
        // - 如果字符串以制表符开头 ("\tabc")，split 后第一个元素是 ""。
        // - 如果字符串为空，split 后是 []，访问 [0] 会 IndexError。
        // 我们的 C 代码模拟这种行为：

        char *address = line_buffer; // 默认地址是整行内容（如果没找到制表符）

        if (tab_ptr != NULL) {
            // 如果找到了制表符，则地址是制表符之前的部分。
            // 通过在制表符位置放置字符串结束符 '\0' 来截断字符串。
            *tab_ptr = '\0';
        }
        // 现在，line_buffer (或 address 指向的地方) 包含了第一个字段的内容。

        // 10. 检查提取出的地址是否为空字符串
        // 这对应 Python 脚本中可能导致 IndexError 的情况（例如，行以制表符开头 "\tbalance"）
        if (strlen(address) == 0) {
            fprintf(stderr, "跳过格式错误的行 (首个字段为空)。\n");
            continue; // 跳过此行，处理下一行
        }

        // 11. 将提取出的地址写入输出文件，并在末尾添加换行符
        fprintf(output_file, "%s\n", address);
    }

    // 12. 关闭文件
    fclose(input_file);
    fclose(output_file);

    // 13. 打印完成信息
    printf("地址提取完成，已保存到 %s 文档中。\n", output_filename);

    return EXIT_SUCCESS; // 返回零表示程序成功执行完毕
}
