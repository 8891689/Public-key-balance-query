//  gcc classify_balance.c -O3 -march=native -o classify_balance
#include <stdio.h>   
#include <stdlib.h>  
#include <string.h>  
#include <stdbool.h> 


#define MAX_LINE_LENGTH 4096 // 增加缓冲区大小，以處理更長的地址或餘額

// 定义默认的输出文件路径
#define OUTPUT_FILE_5_PLUS "balance_5_digits_or_more.txt"
#define OUTPUT_FILE_9_PLUS "balance_9_digits_or_more.txt"

int main(int argc, char *argv[]) {
    FILE *input_file = NULL;
    FILE *output_file_5_plus = NULL;
    FILE *output_file_9_plus = NULL;
    char line_buffer[MAX_LINE_LENGTH]; // 用于存储从文件读取的每一行数据

    // 1. 检查命令行参数数量
    // 程序名 + 输入文件路径 = 2个参数
    if (argc != 2) {
        // 如果参数数量不对，打印用法提示到标准错误流并退出
        fprintf(stderr, "用法: %s <输入文件路径>\n", argv[0]);
        fprintf(stderr, "输出文件将默认为: %s (余额位数 >= 5)\n", OUTPUT_FILE_5_PLUS);
        fprintf(stderr, "                   %s (余额位数 >= 9)\n", OUTPUT_FILE_9_PLUS);
        return EXIT_FAILURE;
    }

    // 2. 获取输入文件路径
    const char *input_filename = argv[1];

    // 3. 打开输入文件 (只读模式)
    input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
        // 如果文件打开失败，打印错误信息并退出
        perror("错误：无法打开输入文件"); // perror 会打印系统错误信息
        return EXIT_FAILURE;
    }

    // 4. 打开第一个输出文件 (写入模式，余额位数 >= 5)
    output_file_5_plus = fopen(OUTPUT_FILE_5_PLUS, "w");
    if (output_file_5_plus == NULL) {
        // 如果文件打开失败，打印错误信息并退出
        perror("错误：无法打开输出文件 (>= 5)");
        fclose(input_file); // 关闭已打开的输入文件
        return EXIT_FAILURE;
    }

    // 5. 打开第二个输出文件 (写入模式，余额位数 >= 9)
    output_file_9_plus = fopen(OUTPUT_FILE_9_PLUS, "w");
    if (output_file_9_plus == NULL) {
        // 如果文件打开失败，打印错误信息并退出
        perror("错误：无法打开输出文件 (>= 9)");
        // 关闭所有已成功打开的文件
        fclose(input_file);
        fclose(output_file_5_plus);
        return EXIT_FAILURE;
    }

    // 6. 逐行读取输入文件并处理
    while (fgets(line_buffer, sizeof(line_buffer), input_file) != NULL) {
        // 获取当前行的实际读取长度
        size_t len = strlen(line_buffer);

        // 7. 移除行尾的换行符 (\n) 或回车符 (\r)
        if (len > 0 && (line_buffer[len - 1] == '\n' || line_buffer[len - 1] == '\r')) {
            line_buffer[len - 1] = '\0';
            if (len > 1 && line_buffer[len - 2] == '\r') {
                line_buffer[len - 2] = '\0';
            }
        }

        // 8. 跳过移除换行符后变为空的行
        if (strlen(line_buffer) == 0) {
            continue;
        }

        // 9. 查找第一个制表符 (\t) 的位置，作为地址和余额的分隔符
        char *tab_ptr = strchr(line_buffer, '\t');

        // 10. 提取地址和余额部分，并检查格式
        char *address = line_buffer; // 地址部分从行头开始
        char *balance_str = NULL;   // 余额字符串部分

        if (tab_ptr != NULL) {
            // 如果找到了制表符
            *tab_ptr = '\0'; // 在制表符位置放置字符串结束符，分隔地址
            balance_str = tab_ptr + 1; // 余额字符串从制表符的下一个字符开始
        }

        // 检查行格式是否正确 (必须有制表符分隔，且余额部分不能是空字符串)
        if (tab_ptr == NULL || *balance_str == '\0') {
            fprintf(stderr, "跳过格式错误的行 (无制表符或余额为空): %s\n", line_buffer);
            continue; // 跳过无法解析的行
        }

        // 11. 计算余额字符串的长度
        size_t balance_length = strlen(balance_str);

        // 12. 根据余额长度将整行数据（原始格式：地址\t余额）写入相应的输出文件
        // 注意：为了写回原始格式，我们需要临时恢复制表符或者重新构造字符串。
        // 最简单的方法是写 地址 + \t + 余额 + \n。

        // 检查是否满足 >= 5 位数的条件
        if (balance_length >= 15) {
            // 使用 fprintf 将地址、制表符、余额和换行符写入文件
            // 注意：address 字符串被修改了 (tab 变成了 \0)
            // balance_str 指向 tab 后面的内容
            fprintf(output_file_5_plus, "%s\t%s\n", address, balance_str);
        }

        // 检查是否满足 >= 9 位数的条件
        // 如果满足 >= 9，则也会满足 >= 5。这里是分别写入两个文件的逻辑。
        if (balance_length >= 19) {
            fprintf(output_file_9_plus, "%s\t%s\n", address, balance_str);
        }
        
        // 注意：不需要将 '\0' 恢复回 '\t'，因为我们在处理下一行时会覆盖 line_buffer。
    }

    // 13. 关闭文件
    fclose(input_file);
    fclose(output_file_5_plus);
    fclose(output_file_9_plus);

    // 14. 打印完成信息
    printf("数据分类完成。\n");
    printf("余额位数 >= 15 的行已保存到 %s\n", OUTPUT_FILE_5_PLUS);
    printf("余额位数 >= 19 的行已保存到 %s\n", OUTPUT_FILE_9_PLUS);

    return EXIT_SUCCESS; // 返回零表示程序成功执行完毕
}
