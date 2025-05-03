#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 计算输入数据的 Keccak-256 哈希值
 *
 * @param in    输入数据指针
 * @param inlen 输入数据的字节数
 * @param out   输出缓冲区，至少需要 32 字节存放 256 位哈希值
 */
void keccak_256(const uint8_t *in, size_t inlen, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // KECCAK_H

