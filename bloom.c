/* bloom.c 
Author: 8891689
https://github.com/8891689
Assist in creation ：ChatGPT 
*/ 
#define _GNU_SOURCE  // for MAP_FAILED
#include "bloom.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* 文件格式标识 */
static const char *BLOOM_MAGIC = "BLOOMv1";

static uint64_t hash1(const void *data, size_t len) {
    const uint8_t *p = data;
    uint64_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ p[i]) * 16777619u;
    return h;
}

static uint64_t hash2(const void *data, size_t len) {
    const uint8_t *p = data;
    uint64_t h = 0;
    for (size_t i = 0; i < len; i++)
        h = h * 31 + p[i];
    return h;
}

BloomFilter *bloom_init(uint64_t n, double p) {
    BloomFilter *bf = calloc(1, sizeof(*bf));
    if (!bf) return NULL;
    /* 计算最优 b、k */
    double ln2 = log(2.0);
    bf->bit_count  = (uint64_t)ceil((- (double)n * log(p)) / (ln2 * ln2));
    bf->hash_count = (uint64_t)ceil(ln2 * (double)bf->bit_count / (double)n);
    bf->byte_count = (bf->bit_count + 7) / 8;
    bf->bit_array  = calloc(bf->byte_count, 1);
    if (!bf->bit_array) { free(bf); return NULL; }
    pthread_rwlock_init(&bf->lock, NULL);
    bf->mmaped = false;
    return bf;
}

void bloom_free(BloomFilter *bf) {
    if (!bf) return;
    if (bf->mmaped) {
        /* mmap 卸载 */
        munmap(bf->bit_array - sizeof(char)*0, bf->byte_count + 0);
    } else {
        free(bf->bit_array);
    }
    pthread_rwlock_destroy(&bf->lock);
    free(bf);
}

void bloom_add(BloomFilter *bf, const void *data, size_t len) {
    uint64_t h1 = hash1(data,len), h2 = hash2(data,len);
    pthread_rwlock_wrlock(&bf->lock);
    for (uint64_t i = 0; i < bf->hash_count; i++) {
        uint64_t idx = (h1 + i*h2) % bf->bit_count;
        bf->bit_array[idx>>3] |= (1u << (idx & 7));
    }
    pthread_rwlock_unlock(&bf->lock);
}

int bloom_check(const BloomFilter *bf, const void *data, size_t len) {
    uint64_t h1 = hash1(data,len), h2 = hash2(data,len);
    pthread_rwlock_rdlock((pthread_rwlock_t*)&bf->lock);
    for (uint64_t i = 0; i < bf->hash_count; i++) {
        uint64_t idx = (h1 + i*h2) % bf->bit_count;
        if ((bf->bit_array[idx>>3] & (1u << (idx & 7))) == 0) {
            pthread_rwlock_unlock((pthread_rwlock_t*)&bf->lock);
            return 0;
        }
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&bf->lock);
    return 1;
}

void bloom_reset(BloomFilter *bf) {
    pthread_rwlock_wrlock(&bf->lock);
    memset(bf->bit_array, 0, bf->byte_count);
    pthread_rwlock_unlock(&bf->lock);
}

/* 将 BloomFilter 序列化到文件 */
int bloom_save(const BloomFilter *bf, const char *filename) {
    int fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd < 0) return -1;
    /* 写 header */
    if (write(fd, BLOOM_MAGIC, 7) != 7) goto err;
    if (write(fd, &bf->bit_count,  sizeof(bf->bit_count))  != sizeof(bf->bit_count))  goto err;
    if (write(fd, &bf->hash_count, sizeof(bf->hash_count)) != sizeof(bf->hash_count)) goto err;
    /* 写位数组 */
    if (write(fd, bf->bit_array, bf->byte_count) != (ssize_t)bf->byte_count) goto err;
    close(fd);
    return 0;
err:
    close(fd);
    return -1;
}

/* 从文件加载（普通读取） */
BloomFilter *bloom_load(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return NULL;
    char magic[8] = {0};
    if (read(fd, magic, 7)!=7 || strcmp(magic,BLOOM_MAGIC)!=0) { close(fd); return NULL; }
    BloomFilter tmp = {0};
    if (read(fd, &tmp.bit_count,  sizeof(tmp.bit_count))  != sizeof(tmp.bit_count))  { close(fd); return NULL; }
    if (read(fd, &tmp.hash_count, sizeof(tmp.hash_count)) != sizeof(tmp.hash_count)) { close(fd); return NULL; }
    tmp.byte_count = (tmp.bit_count+7)/8;
    tmp.bit_array  = malloc(tmp.byte_count);
    if (!tmp.bit_array) { close(fd); return NULL; }
    if (read(fd, tmp.bit_array, tmp.byte_count) != (ssize_t)tmp.byte_count) {
        free(tmp.bit_array); close(fd); return NULL;
    }
    close(fd);
    BloomFilter *bf = malloc(sizeof(*bf));
    *bf = tmp;
    pthread_rwlock_init(&bf->lock, NULL);
    bf->mmaped = false;
    return bf;
}

/* mmap 加载（只读） */
BloomFilter *bloom_mmap_load(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return NULL;
    /* 解析 header */
    char *p = map;
    if (memcmp(p, BLOOM_MAGIC, 7) != 0) { munmap(map,st.st_size); return NULL; }
    p += 7;
    BloomFilter *bf = calloc(1, sizeof(*bf));
    memcpy(&bf->bit_count,  p, sizeof(bf->bit_count));  p += sizeof(bf->bit_count);
    memcpy(&bf->hash_count, p, sizeof(bf->hash_count)); p += sizeof(bf->hash_count);
    bf->byte_count = (bf->bit_count+7)/8;
    bf->bit_array  = (uint8_t*)p;
    pthread_rwlock_init(&bf->lock, NULL);
    bf->mmaped = true;
    return bf;
}

int bloom_mmap_unload(BloomFilter *bf) {
    if (!bf || !bf->mmaped) return -1;
    size_t total = 7 + sizeof(bf->bit_count) + sizeof(bf->hash_count) + bf->byte_count;
    munmap((void*)( (char*)bf->bit_array - (7 + sizeof(bf->bit_count) + sizeof(bf->hash_count)) ), total);
    pthread_rwlock_destroy(&bf->lock);
    free(bf);
    return 0;
}

/* 十六进制字符串 => 二进制 */
static int hex2bin(const char *hex, uint8_t **out, size_t *outlen) {
    size_t len = strlen(hex);
    if (len%2) return -1;
    *outlen = len/2;
    *out = malloc(*outlen);
    for (size_t i=0; i<*outlen; i++) {
        unsigned int byte;
        if (sscanf(hex+2*i, "%2x", &byte)!=1) { free(*out); return -1; }
        (*out)[i] = (uint8_t)byte;
    }
    return 0;
}

int bloom_add_hex(BloomFilter *bf, const char *hexstr) {
    uint8_t *bin; size_t blen;
    if (hex2bin(hexstr,&bin,&blen)) return -1;
    bloom_add(bf, bin, blen);
    free(bin);
    return 0;
}

int bloom_check_hex(const BloomFilter *bf, const char *hexstr) {
    uint8_t *bin; size_t blen;
    if (hex2bin(hexstr,&bin,&blen)) return -1;
    int r = bloom_check(bf, bin, blen);
    free(bin);
    return r;
}

