/*Author: 8891689
 *https://github.com/8891689
 * Assist in creation ：ChatGPT
 */
#include <string.h>
#include <stdio.h>

#include "keccak256.h"

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// Keccak-f[1600] 的 24 轮轮常量
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

// Rho 旋转偏移量
static const int keccakf_rotc[24] = {
    1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
};

// Pi 步骤中的置换索引
static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16,
    8, 21, 24, 4, 15, 23, 19, 13,
    12, 2, 20, 14, 22, 9, 6, 1
};

/**
 * @brief Keccak-f[1600] 状态变换函数，共 24 轮
 *
 * @param st 包含 25 个 uint64_t 状态字的数组
 */
static void keccakf(uint64_t st[25]) {
    int round, i, j;
    uint64_t t, bc[5];
    
    for (round = 0; round < 24; round++) {
        // Theta 步骤：计算每列的奇偶校验并更新状态
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }
        
        // Rho 和 Pi 步骤：数据的位旋转和重排
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            uint64_t temp = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = temp;
        }
        
        // Chi 步骤：非线性置换
        for (j = 0; j < 25; j += 5) {
            uint64_t tmp[5];
            for (i = 0; i < 5; i++) {
                tmp[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= ((~tmp[(i + 1) % 5]) & tmp[(i + 2) % 5]);
            }
        }
        
        // Iota 步骤：轮常量的异或
        st[0] ^= keccakf_rndc[round];
    }
}

/**
 * @brief 计算输入数据的 Keccak-256 哈希值
 *
 * 本实现遵循 Ethereum 对 Keccak-256 的要求：
 * - 使用 Keccak-f[1600] 置换
 * - 速率 rate = 1088 bits (136 bytes)，容量 capacity = 512 bits
 * - Padding 使用 0x01 作为分隔符，最后一字节设置最高位（0x80）
 *
 * @param in    输入数据指针
 * @param inlen 输入数据的字节数
 * @param out   输出缓冲区，至少需要 32 字节存放 256 位哈希值
 */
void keccak_256(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    
    const size_t rate = 136; // 速率，单位字节（1088 bits）
    size_t i;
    
    // 吸收阶段：处理完整的 rate 块
    while (inlen >= rate) {
        for (i = 0; i < rate / 8; i++) {
            uint64_t t = 0;
            for (int j = 0; j < 8; j++) {
                t |= ((uint64_t)in[i * 8 + j]) << (8 * j);
            }
            st[i] ^= t;
        }
        keccakf(st);
        in += rate;
        inlen -= rate;
    }
    
    // 填充：复制剩余数据，并在末尾添加 padding
    uint8_t temp[rate];
    memset(temp, 0, rate);
    memcpy(temp, in, inlen);
    temp[inlen] = 0x01;        // Keccak 的 padding 起始字节（Ethereum 使用 0x01）
    temp[rate - 1] |= 0x80;      // 最后一个字节的最高位置 1
    
    // 吸收最后填充的区块
    for (i = 0; i < rate / 8; i++) {
        uint64_t t = 0;
        for (int j = 0; j < 8; j++) {
            t |= ((uint64_t)temp[i * 8 + j]) << (8 * j);
        }
        st[i] ^= t;
    }
    keccakf(st);
    
    // 挤出阶段：输出前 32 字节（256 位）
    for (i = 0; i < 4; i++) {
        uint64_t t = st[i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(t & 0xFF);
            t >>= 8;
        }
    }
}



