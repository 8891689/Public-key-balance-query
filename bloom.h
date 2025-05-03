/* bloom.h 
Author: 8891689
https://github.com/8891689
Assist in creation ：ChatGPT 
*/ 
#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/** BloomFilter 结构体 **/
typedef struct {
    uint64_t  bit_count;    // 位总数 (b)
    uint64_t  byte_count;   // 字节总数 = ceil(b/8)
    uint64_t  hash_count;   // 哈希函数个数 (k)
    uint8_t  *bit_array;    // 位数组
    bool      mmaped;       // 是否通过 mmap 加载
    pthread_rwlock_t lock;  // 读写锁，保证并发安全
} BloomFilter;

/** 初始化/销毁 **/
BloomFilter *bloom_init(uint64_t expected_entries,
                        double false_positive_rate);
void          bloom_free(BloomFilter *bf);

/** 核心操作 **/
void          bloom_add(BloomFilter *bf,
                        const void *data, size_t len);
int           bloom_check(const BloomFilter *bf,
                          const void *data, size_t len);
void          bloom_reset(BloomFilter *bf);

/** 文件持久化 **/
int           bloom_save(const BloomFilter *bf,
                         const char *filename);
BloomFilter  *bloom_load(const char *filename);

/** mmap 加载（只读） **/
BloomFilter  *bloom_mmap_load(const char *filename);
int           bloom_mmap_unload(BloomFilter *bf);

/** 十六进制字符串接口 **/
int           bloom_add_hex(BloomFilter *bf,
                            const char *hexstr);
int           bloom_check_hex(const BloomFilter *bf,
                              const char *hexstr);

#ifdef __cplusplus
}
#endif

#endif /* BLOOM_H */

