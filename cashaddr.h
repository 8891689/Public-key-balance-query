/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef CASHADDR_H
#define CASHADDR_H

#include <stddef.h>
#include <stdint.h>

/* 解析后的现金地址结果 */
typedef struct {
    char prefix[32];     /* 地址前缀 */
    int version;         /* 版本 */
    char type[16];       /* 地址类型，例如 "P2PKH" 或 "P2SH" 或 "未知类型" */
    char hash160[41];    /* 40字符十六进制字符串，附带结束符 */
} CashAddrResult;

/* 解码现金地址
 * 参数 address：输入地址字符串
 * 参数 result：输出解析结果（注意：需要保证结构体指针有效）
 * 返回 0 表示成功，非0表示失败
 */
int decode_cashaddr(const char *address, CashAddrResult *result);

/* 编码现金地址
 * 参数 prefix：地址前缀
 * 参数 version：版本号（0-7）
 * 参数 type：地址类型（"P2PKH"或"P2SH"）
 * 参数 hash160：20字节哈希160的十六进制字符串（40字符）
 * 参数 out_address：输出编码后的地址字符串缓冲区
 * 参数 out_size：输出缓冲区大小
 * 返回 0 表示成功，非0表示失败
 */
int encode_cashaddr(const char *prefix, int version, const char *type, const char *hash160,
                    char *out_address, size_t out_size);

#endif /* CASHADDR_H */

