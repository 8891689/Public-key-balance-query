// gcc main.c sha256.c ripemd160.c base58.c bech32.c keccak256.c cashaddr.c bloom.c -O3 -march=native -o address_checker libsecp256k1.a -lm -pthread -Wall -Wextra
// Author: 8891689
// https://github.com/8891689
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <ctype.h> // For isspace
#include <sys/time.h> // For gettimeofday
#include <inttypes.h> // For PRIu64
#include <pthread.h> // For multithreading
#include <unistd.h>  // For sleep/usleep or other utilities if needed <--- Corrected

/* Global debug flag */
bool g_debug = false;

// Use the official secp256k1 library header
#include <secp256k1.h>

// Include your custom headers
#include "bloom.h"
#include "sha256.h"
#include "ripemd160.h"
#include "base58.h"
#include "bech32.h"
#include "keccak256.h"
#include "cashaddr.h" // Assumed interface: encode_cashaddr


/* --- Simple Hash Set Implementation for Secondary Confirmation --- */

// Node structure for separate chaining
typedef struct HashSetNode {
    char *key;
    struct HashSetNode *next;
} HashSetNode;

// Hash Set structure
typedef struct {
    HashSetNode **buckets;
    size_t capacity; // Number of buckets
    size_t count;    // Number of elements
} HashSet;

// Simple hash function for strings (djb2)
static size_t hash_string(const char *str) {
    size_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Initialize Hash Set
HashSet* hashset_init(size_t initial_capacity) {
    if (initial_capacity == 0) initial_capacity = 10000; // Default capacity
    HashSet *hs = (HashSet *)malloc(sizeof(HashSet));
    if (!hs) return NULL;
    hs->capacity = initial_capacity;
    hs->count = 0;
    hs->buckets = (HashSetNode **)calloc(hs->capacity, sizeof(HashSetNode *));
    if (!hs->buckets) {
        free(hs);
        return NULL;
    }
    return hs;
}

// Add a key to the Hash Set (returns 0 on success, -1 on failure, 1 if already exists)
int hashset_add(HashSet *hs, const char *key) {
    if (!hs || !key) return -1;

    size_t index = hash_string(key) % hs->capacity;

    // Check if key already exists (linear scan in bucket)
    HashSetNode *node = hs->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return 1; // Key already exists
        }
        node = node->next;
    }

    // Key does not exist, add new node
    HashSetNode *new_node = (HashSetNode *)malloc(sizeof(HashSetNode));
    if (!new_node) return -1;
    new_node->key = strdup(key); // Duplicate the key string
    if (!new_node->key) {
        free(new_node);
        return -1;
    }
    new_node->next = hs->buckets[index];
    hs->buckets[index] = new_node;
    hs->count++;

    // Optional: Resize hash set if load factor gets too high (e.g., count > capacity * 2)
    // For simplicity, we skip resizing in this example.

    return 0; // Success
}

// Check if a key exists in the Hash Set
bool hashset_contains(HashSet *hs, const char *key) {
    if (!hs || !key) return false;
    size_t index = hash_string(key) % hs->capacity;
    HashSetNode *node = hs->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return true; // Key found
        }
        node = node->next;
    }
    return false; // Key not found
}

// Destroy Hash Set and free memory
void hashset_destroy(HashSet *hs) {
    if (!hs) return;
    for (size_t i = 0; i < hs->capacity; i++) {
        HashSetNode *node = hs->buckets[i];
        while (node) {
            HashSetNode *temp = node;
            node = node->next;
            free(temp->key); // Free the key string
            free(temp);      // Free the node
        }
    }
    free(hs->buckets); // Free the bucket array
    free(hs);          // Free the HashSet struct
}
/* --- End Simple Hash Set Implementation --- */


/* Threading Globals and Structures */
typedef struct {
    char *pubkey_hex; // Dynamically allocated hex string
} work_item_t;

// Work Queue using a circular buffer
typedef struct {
    work_item_t *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t can_produce;
    pthread_cond_t can_consume;
    bool producer_done; // Flag to signal consumers no more work is coming
} work_queue_t;

// Data passed to each worker thread
typedef struct {
    BloomFilter *bf;
    HashSet *target_address_hs; // <-- Hash Set Pointer added to worker data
    const char *coin_type_to_match;
    bool check_all_coins;
    FILE *output_file;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *count_mutex;
    long long *processed_count; // Shared counter for total keys processed
    work_queue_t *work_queue;
    secp256k1_context *ctx;
    bool debug; // Pass debug flag to worker
} worker_data_t;


/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);
char *trim_whitespace(char *str);
long count_lines_in_file(const char *filename, bool debug);

// Function to standardize address format for lookup (remove 0x, HRP) - Needed to match generated addresses
char *standardize_address_for_lookup(const char *address_in, bool debug);

// Function to load addresses into BOTH Bloom Filter and Hash Set
int load_addresses_into_data_structures(const char *filename, BloomFilter *bf, HashSet *hs, bool debug);


/* 地址生成函数 (Takes serialized public key bytes) */
char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Generates without "0x"
char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Legacy
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Generates without HRP
char *generate_bitcoingold_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);


/* Work Queue Functions */
int queue_init(work_queue_t *q, size_t capacity) {
    q->items = (work_item_t *)malloc(capacity * sizeof(work_item_t));
    if (!q->items) return -1;
    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->producer_done = false;
    if (pthread_mutex_init(&q->mutex, NULL) != 0) { free(q->items); return -1; }
    if (pthread_cond_init(&q->can_produce, NULL) != 0) { pthread_mutex_destroy(&q->mutex); free(q->items); return -1; }
    if (pthread_cond_init(&q->can_consume, NULL) != 0) { pthread_cond_destroy(&q->can_produce); pthread_mutex_destroy(&q->mutex); free(q->items); return -1; }
    return 0;
}

void queue_destroy(work_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count > 0) {
        work_item_t item = q->items[q->head];
        q->head = (q->head + 1) % q->capacity;
        if (item.pubkey_hex) free(item.pubkey_hex);
        q->count--;
    }
    pthread_mutex_unlock(&q->mutex);

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->can_produce);
    pthread_cond_destroy(&q->can_consume);
    free(q->items);
}

int queue_enqueue(work_queue_t *q, work_item_t item) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == q->capacity && !q->producer_done) {
        pthread_cond_wait(&q->can_produce, &q->mutex);
    }
    if (q->producer_done && q->count == q->capacity) {
         pthread_mutex_unlock(&q->mutex);
         return -1;
    }
    q->items[q->tail] = item;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->can_consume);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int queue_dequeue(work_queue_t *q, work_item_t *item) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->producer_done) {
        pthread_cond_wait(&q->can_consume, &q->mutex);
    }
    if (q->count == 0 && q->producer_done) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    *item = q->items[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_cond_signal(&q->can_produce);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}


/* Worker Thread Function */
void *worker_process_key(void *arg) {
    worker_data_t *data = (worker_data_t *)arg;
    work_item_t item;

    while (queue_dequeue(data->work_queue, &item) == 0) {
        char *pub_hex_line = item.pubkey_hex;
        size_t hex_len = strlen(pub_hex_line);

        if (hex_len != 66 && hex_len != 130) {
             if (data->debug) fprintf(stderr, "Debug: Skipping invalid public key hex length (%zu): %s\n", hex_len, pub_hex_line);
             free(pub_hex_line);
             pthread_mutex_lock(data->count_mutex); (*data->processed_count)++; pthread_mutex_unlock(data->count_mutex);
             continue;
        }

        uint8_t pub_bin_input[65];
        size_t pub_bin_input_len = hex_len / 2;
        if (hex2bin(pub_hex_line, pub_bin_input, pub_bin_input_len) != 0) {
            if (data->debug) fprintf(stderr, "Debug: Skipping invalid public key hex format: %s\n", pub_hex_line);
            free(pub_hex_line);
            pthread_mutex_lock(data->count_mutex); (*data->processed_count)++; pthread_mutex_unlock(data->count_mutex);
            continue;
        }

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(data->ctx, &pubkey, pub_bin_input, pub_bin_input_len)) {
            if (data->debug) fprintf(stderr, "Debug: Skipping unparseable public key (not on curve?): %s\n", pub_hex_line);
            free(pub_hex_line);
            pthread_mutex_lock(data->count_mutex); (*data->processed_count)++; pthread_mutex_unlock(data->count_mutex);
            continue;
        }

        uint8_t pub_comp_bytes[33]; size_t pub_comp_len = sizeof(pub_comp_bytes);
        if (!secp256k1_ec_pubkey_serialize(data->ctx, pub_comp_bytes, &pub_comp_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
             if (data->debug) fprintf(stderr, "Debug: Failed to serialize compressed public key for: %s\n", pub_hex_line);
             free(pub_hex_line);
             pthread_mutex_lock(data->count_mutex); (*data->processed_count)++; pthread_mutex_unlock(data->count_mutex);
             continue;
        }

        uint8_t pub_uncomp_bytes[65]; size_t pub_uncomp_len = sizeof(pub_uncomp_bytes);
        if (!secp256k1_ec_pubkey_serialize(data->ctx, pub_uncomp_bytes, &pub_uncomp_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
             if (data->debug) fprintf(stderr, "Debug: Failed to serialize uncompressed public key for: %s\n", pub_hex_line);
             free(pub_hex_line);
             pthread_mutex_lock(data->count_mutex); (*data->processed_count)++; pthread_mutex_unlock(data->count_mutex);
             continue;
        }

        // --- Generate Addresses and Check Bloom Filter + Hash Set ---
        bool confirmed_match_found = false;
        char matched_type_name[50] = {0};
        char matched_comp_status[20] = {0};
        char matched_coin_name[10] = {0};
        char *matched_address_str = NULL;

        struct {
            char* (*generator)(const uint8_t*, size_t, bool);
            const uint8_t *bytes;
            size_t len;
            const char *type_name;
            const char *comp_status;
            const char *coin_internal_name;
        } address_attempts[] = {
            {generate_btc_p2pkh_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "BTC"},
            {generate_btc_p2pkh_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "BTC"},
            {generate_btc_p2sh_p2wpkh_address, pub_comp_bytes, pub_comp_len, "P2SH-P2WPKH", "Compressed", "BTC"},
            {generate_btc_p2sh_p2wpkh_address, pub_uncomp_bytes, pub_uncomp_len, "P2SH-P2WPKH", "Uncompressed", "BTC"},
            {generate_btc_bech32_address, pub_comp_bytes, pub_comp_len, "BECH32 (P2WPKH)", "Compressed", "BTC"},
            {generate_btc_bech32_address, pub_uncomp_bytes, pub_uncomp_len, "BECH32 (P2WPKH)", "Uncompressed", "BTC"},
            {generate_eth_address, pub_uncomp_bytes, pub_uncomp_len, "ETH", "", "ETH"}, // ETH uses uncompressed key (no 0x04 prefix in hash), generated without "0x"
            {generate_dogecoin_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "DOGE"},
            {generate_dogecoin_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "DOGE"},
            {generate_litecoin_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "LTC"},
            {generate_litecoin_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "LTC"},
            {generate_dash_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "DASH"},
            {generate_dash_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "DASH"},
            {generate_zcash_address, pub_comp_bytes, pub_comp_len, "P2PKH (Transparent)", "Compressed", "ZEC"},
            {generate_zcash_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH (Transparent)", "Uncompressed", "ZEC"},
            //{generate_bitcoincash_address, pub_comp_bytes, pub_comp_len, "Legacy P2PKH", "Compressed", "BCH"},
            //{generate_bitcoincash_address, pub_uncomp_bytes, pub_uncomp_len, "Legacy P2PKH", "Uncompressed", "BCH"},
            {generate_bitcoincash_cashaddr, pub_comp_bytes, pub_comp_len, "CashAddr P2PKH", "Compressed", "BCH"}, // CashAddr (no prefix generated)
            {generate_bitcoincash_cashaddr, pub_uncomp_bytes, pub_uncomp_len, "CashAddr P2PKH", "Uncompressed", "BCH"}, // CashAddr (no prefix generated)
            {generate_bitcoingold_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "BTG"},
            {generate_bitcoingold_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "BTG"},
        };

        for (size_t i = 0; i < sizeof(address_attempts) / sizeof(address_attempts[0]); ++i) {

            if (!data->check_all_coins && strcmp(address_attempts[i].coin_internal_name, data->coin_type_to_match) != 0) {
                 continue;
             }

            char *generated_address = address_attempts[i].generator(address_attempts[i].bytes, address_attempts[i].len, data->debug);

            if (generated_address && strlen(generated_address) > 0) {
                 if (data->debug) {
                     const char *display_coin = address_attempts[i].coin_internal_name;
                     const char *comp_status = strlen(address_attempts[i].comp_status) > 0 ? address_attempts[i].comp_status : "";
                     const char *type_name = address_attempts[i].type_name;
                     if (strlen(comp_status) > 0) fprintf(stderr, "Debug: Generated %s: %s (%s): %s\n", display_coin, type_name, comp_status, generated_address);
                     else fprintf(stderr, "Debug: Generated %s: %s: %s\n", display_coin, type_name, generated_address);
                 }

                 // --- Primary Filter: Bloom Filter Check ---
                 if (bloom_check(data->bf, generated_address, strlen(generated_address))) {

                     if (data->debug) fprintf(stderr, "Debug: BF Hit for %s. Checking Hash Set...\n", generated_address);

                     // --- Secondary Confirmation: Hash Set Lookup ---
                     if (hashset_contains(data->target_address_hs, generated_address)) {
                         // --- Found a TRUE Positive Match! ---
                         if (data->debug) fprintf(stderr, "Debug: Hash Set Hit for %s. CONFIRMED MATCH.\n", generated_address);
                         confirmed_match_found = true;
                         strncpy(matched_coin_name, address_attempts[i].coin_internal_name, sizeof(matched_coin_name) - 1);
                         strncpy(matched_type_name, address_attempts[i].type_name, sizeof(matched_type_name) - 1);
                         strncpy(matched_comp_status, address_attempts[i].comp_status, sizeof(matched_comp_status) - 1);
                         matched_address_str = strdup(generated_address);
                         if (!matched_address_str) {
                              fprintf(stderr, "Error: Failed to allocate memory for confirmed match string for %s. Skipping output.\n", pub_hex_line);
                              confirmed_match_found = false; // Clear flag if allocation failed
                         }
                         free(generated_address); // Free temporary string
                         generated_address = NULL; // Avoid double free
                         break; // Exit address_attempts loop for this key
                     } else {
                          if (data->debug) fprintf(stderr, "Debug: Hash Set Miss for %s. This was a FALSE POSITIVE in BF.\n", generated_address);
                          // This was a false positive, continue checking other address types for this key
                     }
                 } else {
                     // BF missed -> definitely not in the target set (True Negative)
                     //if (data->debug) fprintf(stderr, "Debug: BF Miss for %s.\n", generated_address);
                     // Continue checking other address types for this key
                 }

                if (generated_address) { // Check if it wasn't freed inside the loop
                    free(generated_address);
                    generated_address = NULL;
                }
            } else {
                 if (data->debug && generated_address == NULL) {
                      const char *display_coin = address_attempts[i].coin_internal_name;
                      const char *comp_status = strlen(address_attempts[i].comp_status) > 0 ? address_attempts[i].comp_status : "";
                      const char *type_name = address_attempts[i].type_name;
                       if (strlen(comp_status) > 0) fprintf(stderr, "Debug: Failed to generate %s: %s (%s) for %s\n", display_coin, type_name, comp_status, pub_hex_line);
                       else fprintf(stderr, "Debug: Failed to generate %s: %s for %s\n", display_coin, type_name, pub_hex_line);
                 }
            }
        }

        // --- Output Confirmed Match if Found ---
        if (confirmed_match_found) {
            pthread_mutex_lock(data->output_mutex);
            if (data->debug) {
                 fprintf(data->output_file, "%s %s %s (%s): %s -> [CONFIRMED MATCH]\n",
                         pub_hex_line, matched_coin_name, matched_type_name, matched_comp_status, matched_address_str);
            } else {
                 // Non-debug format (to output file): ONLY 公鑰
                 fprintf(data->output_file, "%s\n", pub_hex_line);
            }
            fflush(data->output_file);
            pthread_mutex_unlock(data->output_mutex);

            if (data->debug) fprintf(stderr, "Debug: Confirmed match outputted for %s\n", pub_hex_line);
        }

        // --- Cleanup for this work item ---
        if (matched_address_str) {
            free(matched_address_str);
        }

        pthread_mutex_lock(data->count_mutex);
        (*data->processed_count)++;
        pthread_mutex_unlock(data->count_mutex);
        free(pub_hex_line);

    }
    return NULL;
}

/* --- Implementation of Helper Functions --- */

int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || hex_len % 2 != 0 || bin_len < hex_len / 2) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

void hash160(const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t sha[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, sha);
    RIPEMD160_CTX rip_ctx;
    ripemd160_init(&rip_ctx);
    ripemd160_update(&rip_ctx, sha, 32);
    ripemd160_final(&rip_ctx, out);
}

int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);
    uint8_t hash1[32], hash2[32];
    sha256(payload, 21, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[25]; // 21 payload + 4 checksum = 25 bytes
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);

    // --- 添加此 Debug 打印 ---
    // 注意：此函數沒有 debug 參數，使用全局的 g_debug
     if (g_debug) {
         char full_hex[51]; // 25 bytes * 2 chars/byte + null terminator
         bin2hex(full, 25, full_hex);
         //fprintf(stderr, "Debug: Base58Check Encode (Version 0x%02x) - Input 25 bytes to b58enc: %s\n", version, full_hex);
     }
    // --- 結束添加 ---

    size_t encoded_len = addr_len;
    if (!b58enc(address, &encoded_len, full, 25)) return -1; // 这里使用 25 bytes，看起来是对的
    return 0;
}

char *trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

long count_lines_in_file(const char *filename, bool debug) {
    FILE *f = fopen(filename, "r");
    if (!f) { if (debug) fprintf(stderr, "Debug: count_lines_in_file: Cannot open file '%s'\n", filename); return -1; }
    long count = 0; char buffer[8192]; size_t bytes_read; bool last_char_newline = true;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < bytes_read; ++i) if (buffer[i] == '\n') { count++; last_char_newline = true; } else last_char_newline = false;
    }
    if (!last_char_newline && bytes_read > 0) count++; // Handle files without trailing newline
    // Handle non-empty files that don't end with newline OR are single lines
     if (count == 0 && bytes_read > 0) count = 1; // Count single line files without newline
     if (count > 0 && !last_char_newline) {} // Already counted if last line had char

    fclose(f);
    if (debug) fprintf(stderr, "Debug: count_lines_in_file: Counted %ld lines in '%s'.\n", count, filename);
    return count;
}

// Function to standardize address format for lookup (remove 0x, HRP)
// Returns dynamically allocated string, must be freed
char *standardize_address_for_lookup(const char *address_in, bool debug) {
    if (!address_in || strlen(address_in) == 0) return NULL;

    const char *processed_address = address_in;
    size_t len = strlen(address_in);

    // Handle ETH: Remove leading "0x" if present and address is long enough to be a hex address
    if (len >= 42 && processed_address[0] == '0' && (processed_address[1] == 'x' || processed_address[1] == 'X')) {
        // Basic check if it looks like a hex string after 0x
        bool looks_like_hex = true;
        for(size_t i = 2; i < len; ++i) {
            if (!isxdigit((unsigned char)processed_address[i])) {
                looks_like_hex = false;
                break;
            }
        }
        if (looks_like_hex) {
            processed_address += 2; // Skip "0x"
            len -= 2;
             if (debug) fprintf(stderr, "Debug: Standardizing ETH address, removed '0x': '%s' -> '%s'\n", address_in, processed_address);
        }
    }

    // Handle BCH CashAddr: Remove HRP (e.g., "bitcoincash:") if present
    const char *colon_pos = strchr(processed_address, ':');
    if (colon_pos) {
        // Basic check: HRP usually contains only lowercase letters/digits/hyphens, and address part follows specific encoding.
        // A simple check is if there's a colon AND the part after the colon is not empty.
        if (*(colon_pos + 1) != '\0') {
             processed_address = colon_pos + 1; // Skip HRP and colon
             len = strlen(processed_address);
              if (debug) fprintf(stderr, "Debug: Standardizing BCH CashAddr, removed HRP: '%s' -> '%s'\n", address_in, processed_address);
        }
    }

    // Allocate and return the standardized string
    char *standardized = strdup(processed_address);
    if (!standardized) {
        if (debug) fprintf(stderr, "Error: Malloc failed during address standardization for '%s'\n", address_in);
        return NULL;
    }
    return standardized;
}


// Function to load addresses into BOTH Bloom Filter and Hash Set
// Returns the number of unique addresses successfully added to the Hash Set, or -1 on file error
int load_addresses_into_data_structures(const char *filename, BloomFilter *bf, HashSet *hs, bool debug) {
    FILE *f = fopen(filename, "r");
    if (!f) {
         if (debug) fprintf(stderr, "Debug: load_addresses_into_data_structures: Cannot open file '%s'\n", filename);
        return -1; // Indicate error
    }

    char line[256];
    size_t addresses_added_to_hs = 0; // Count unique addresses actually added to HS
    while (fgets(line, sizeof(line), f)) {
        char *trimmed_line = trim_whitespace(line);

        if (strlen(trimmed_line) > 0) {
             // Standardize the address format before adding to BF and HS
            char *standardized_address = standardize_address_for_lookup(trimmed_line, debug);

            if (standardized_address) {
                // Add to Bloom Filter (allows duplicates, probability check)
                bloom_add(bf, standardized_address, strlen(standardized_address));
                 //if (debug) fprintf(stderr, "Debug: Added '%s' to BF (standardized from '%s').\n", standardized_address, trimmed_line); // Too verbose

                // Add to Hash Set (only adds unique, deterministic check)
                int add_status = hashset_add(hs, standardized_address);
                if (add_status == 0) { // Successfully added (it was unique)
                     addresses_added_to_hs++;
                     //if (debug) fprintf(stderr, "Debug: Added '%s' to HS (standardized from '%s'). HS count: %zu\n", standardized_address, trimmed_line, hs->count); // Too verbose
                } else if (add_status == 1) {
                     // Address already exists in HS, skip
                     //if (debug) fprintf(stderr, "Debug: '%s' already exists in HS (standardized from '%s'). HS count: %zu\n", standardized_address, trimmed_line, hs->count); // Too verbose
                } else { // add_status == -1 (malloc failed)
                     fprintf(stderr, "Error: Failed to add standardized address '%s' (from '%s') to Hash Set due to memory error. Skipping.\n", standardized_address, trimmed_line);
                }

                free(standardized_address); // Free the dynamically allocated standardized string
            } else {
                 if (debug) fprintf(stderr, "Debug: Skipping line after standardization failed: '%s'.\n", trimmed_line);
            }
        } else {
             // if (debug) fprintf(stderr, "Debug: Skipping empty or whitespace-only line.\n"); // Too verbose
        }
    }

    fclose(f);
    if (debug) fprintf(stderr, "Debug: Finished loading addresses into data structures. Added %zu unique addresses to Hash Set.\n", addresses_added_to_hs);

    return addresses_added_to_hs; // Return count of unique addresses added to Hash Set
}


/* --- Implementation of Address Generation Functions --- */
char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];
    hash160(pub_bytes, pub_len, hash_160);

    // --- 添加此 Debug 打印 ---
    if (debug) {
        char hash160_hex[41]; // 20 bytes * 2 chars/byte + null terminator
        bin2hex(hash_160, 20, hash160_hex);
        //fprintf(stderr, "Debug: BTC P2PKH Gen - PubLen: %zu, Calculated Hash160: %s\n", pub_len, hash160_hex);
    }
    // --- 結束添加 ---

    char *address = (char *)malloc(100); // 100 is a safe buffer size for Base58
    if (!address) { /* ... error handling ... */ return NULL; }

    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    uint8_t pubkey_hash[20]; hash160(pub_bytes, pub_len, pubkey_hash);
    uint8_t redeem_script[22] = {0x00, 0x14};
    memcpy(redeem_script + 2, pubkey_hash, 20);
    uint8_t redeem_script_hash160[20]; hash160(redeem_script, 22, redeem_script_hash160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x05, redeem_script_hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    uint8_t pubkey_hash[20]; hash160(pub_bytes, pub_len, pubkey_hash);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (segwit_addr_encode(address, "bc", 0, pubkey_hash, 20) != 1) { free(address); if (debug) fprintf(stderr, "Debug: segwit_addr_encode failed.\n"); return NULL; }
    return address;
}

// Generates ETH address without "0x" prefix
char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 65 || pub_bytes[0] != 0x04) {
        if (debug) fprintf(stderr, "Debug: generate_eth_address: Invalid pubkey byte length (%zu) or prefix (0x%02x).\n", pub_len, pub_len > 0 ? pub_bytes[0] : 0);
        return NULL;
    }
    uint8_t keccak_hash[32];
    keccak_256(pub_bytes + 1, 64, keccak_hash); // Hash the 64 bytes after 0x04
    char *address = (char *)malloc(41); // 40 hex chars + null
    if (!address) { if (debug) fprintf(stderr, "Debug: generate_eth_address: Malloc failed.\n"); return NULL; }
    bin2hex(keccak_hash + 12, 20, address); // Use last 20 bytes of hash
    return address; // Returns without "0x"
}

char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x1E, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x30, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x4C, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    uint8_t zcash_version[2] = {0x1C, 0xB8}; uint8_t payload[22]; memcpy(payload, zcash_version, 2); memcpy(payload + 2, hash_160, 20);
    uint8_t hash1[32], hash2[32]; sha256(payload, 22, hash1); sha256(hash1, 32, hash2);
    uint8_t full[26]; memcpy(full, payload, 22); memcpy(full + 22, hash2, 4);
    size_t encoded_len = 100;
    if (!b58enc(address, &encoded_len, full, 26)) { free(address); return NULL; }
    return address;
}

char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// Generates BCH CashAddr address WITHOUT prefix
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
     (void)debug;
     if (pub_len != 33 && pub_len != 65) { if (debug) fprintf(stderr, "Debug: generate_bitcoincash_cashaddr: Invalid pubkey byte length %zu.\n", pub_len); return NULL; }
    uint8_t hash_160[20] = {0}; hash160(pub_bytes, pub_len, hash_160);
    char hash_hex[41] = {0}; bin2hex(hash_160, 20, hash_hex);
    char address_with_prefix[128] = {0};
    const char *hrp_prefix = "bitcoincash";
    int cashaddr_version = 0;
    const char *cashaddr_type_str = "P2PKH";
    // Corrected misleading indentation warning
    if (encode_cashaddr(hrp_prefix, cashaddr_version, cashaddr_type_str, hash_hex, address_with_prefix, sizeof(address_with_prefix)) != 0) {
        if (debug) {
            fprintf(stderr, "Debug: Encoding Bitcoin Cash CashAddr failed for hex: %s\n", hash_hex);
        }
        return NULL;
    }
    char *colon_pos = strchr(address_with_prefix, ':');
    if (colon_pos == NULL) { if (debug) fprintf(stderr, "Debug: Generated CashAddr with HRP but no colon found: '%s' for hex %s\n", address_with_prefix, hash_hex); return NULL; }
    const char *address_without_prefix_start = colon_pos + 1;
    char *address_to_return = strdup(address_without_prefix_start);
    if (address_to_return == NULL) { if (debug) fprintf(stderr, "Debug: generate_bitcoincash_cashaddr: Malloc failed for prefix-less string.\n"); return NULL; }
    return address_to_return; // Returns without HRP
}

char *generate_bitcoingold_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x26, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}


int main(int argc, char **argv) {
    const char *pubkey_file = NULL;
    const char *address_file = NULL;
    const char *coin_type_to_match = NULL;
    bool check_all_coins = false;
    const char *output_filename = NULL;
    int num_threads = 4;
    FILE *output_file = stdout;
    secp256k1_context *ctx = NULL;

    BloomFilter *target_address_bf = NULL;
    HashSet *target_address_hs = NULL; // <-- Hash Set Pointer

    pthread_t *threads = NULL;
    worker_data_t *worker_data = NULL;
    work_queue_t work_queue;
    pthread_mutex_t output_mutex;
    pthread_mutex_t count_mutex;
    long long processed_count = 0;

    bool coin_flag_found = false;
    bool all_flag_found = false;
    bool input_file_found = false;
    bool address_file_found = false;

    // --- Command Line Argument Parsing ---
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) { if (i + 1 < argc) { pubkey_file = argv[++i]; input_file_found = true; } else { fprintf(stderr, "Error: -i requires a public key file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-f") == 0) { if (i + 1 < argc) { address_file = argv[++i]; address_file_found = true; } else { fprintf(stderr, "Error: -f requires an address file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-t") == 0) { if (i + 1 < argc) { num_threads = atoi(argv[++i]); if (num_threads <= 0) { fprintf(stderr, "Error: Number of threads must be a positive integer.\n"); return 1; } } else { fprintf(stderr, "Error: -t requires a number of threads.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-o") == 0) { if (i + 1 < argc) { output_filename = argv[++i]; } else { fprintf(stderr, "Error: -o requires an output file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-bug") == 0) { g_debug = true; }
        else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-d") == 0 ||
                 strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-z") == 0 ||
                 strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-g") == 0) {
             if (coin_flag_found || all_flag_found) { fprintf(stderr, "Error: Only one coin type flag (-b, -e, etc.) or -all is allowed.\n"); return 1; }
             coin_flag_found = true;
             if (strcmp(argv[i], "-b") == 0) coin_type_to_match = "BTC"; else if (strcmp(argv[i], "-e") == 0) coin_type_to_match = "ETH";
             else if (strcmp(argv[i], "-d") == 0) coin_type_to_match = "DOGE"; else if (strcmp(argv[i], "-l") == 0) coin_type_to_match = "LTC";
             else if (strcmp(argv[i], "-a") == 0) coin_type_to_match = "DASH"; else if (strcmp(argv[i], "-z") == 0) coin_type_to_match = "ZEC";
             else if (strcmp(argv[i], "-c") == 0) coin_type_to_match = "BCH"; else if (strcmp(argv[i], "-g") == 0) coin_type_to_match = "BTG";
        } else if (strcmp(argv[i], "-all") == 0) {
             if (coin_flag_found || all_flag_found) { fprintf(stderr, "Error: Only one coin type flag (-b, -e, etc.) or -all is allowed.\n"); return 1; }
             all_flag_found = true; check_all_coins = true;
        }
        else { fprintf(stderr, "Error: Unknown argument '%s'.\n", argv[i]); goto usage_error; }
    }

    if (!input_file_found || !address_file_found || (!coin_flag_found && !all_flag_found) ) {
        fprintf(stderr, "Error: Missing required arguments (-i, -f, and one coin type flag or -all).\n");
        goto usage_error;
    }

    // --- Initialize secp256k1 context ---
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) { fprintf(stderr, "Error: Failed to create secp256k1 context.\n"); return 1; }
    if (g_debug) fprintf(stderr, "Debug: secp256k1 context created.\n");

    // --- Bloom Filter and Hash Set Initialization ---
    fprintf(stderr, "Info: Counting lines in target address file '%s'...\n", address_file);
    long estimated_entries = count_lines_in_file(address_file, g_debug);
    if (estimated_entries <= 0) { fprintf(stderr, "Error: Could not count lines or found no potential entries in address file '%s'.\n", address_file); secp256k1_context_destroy(ctx); return 1; }

    double false_positive_rate = 0.000001; // 1 in a million
    fprintf(stderr, "Info: Initializing Bloom Filter for approx %ld entries with FPR %.6f...\n", estimated_entries, false_positive_rate);
    target_address_bf = bloom_init((uint64_t)estimated_entries, false_positive_rate);
    if (!target_address_bf) { fprintf(stderr, "Error: Failed to initialize Bloom Filter.\n"); secp256k1_context_destroy(ctx); return 1; }
    fprintf(stderr, "Info: Bloom Filter initialized (bit_count=%" PRIu64 ", byte_count=%" PRIu64 ", hash_count=%" PRIu64 ").\n",
            target_address_bf->bit_count, target_address_bf->byte_count, target_address_bf->hash_count);

    fprintf(stderr, "Info: Initializing Hash Set...\n");
    // Initialize Hash Set capacity based on estimated entries (e.g., 2x for lower collision)
    target_address_hs = hashset_init((size_t)estimated_entries * 2); // <-- Initialize Hash Set
    if (!target_address_hs) {
         fprintf(stderr, "Error: Failed to initialize Hash Set.\n");
         bloom_free(target_address_bf);
         secp256k1_context_destroy(ctx);
         return 1;
    }
    fprintf(stderr, "Info: Hash Set initialized (capacity=%zu).\n", target_address_hs->capacity);


    // Load target addresses into BOTH Bloom Filter and Hash Set
    fprintf(stderr, "Info: Loading target addresses into Bloom Filter and Hash Set from '%s'...\n", address_file);
    size_t actual_added_count = load_addresses_into_data_structures(address_file, target_address_bf, target_address_hs, g_debug); // <-- Use new load function
    if (actual_added_count <= 0) { // Check <= 0 because load_addresses_into_data_structures returns added count or -1 on file open error
        if (actual_added_count == 0) {
             fprintf(stderr, "Error: No valid addresses loaded into data structures from '%s'. File might be empty or contain only invalid/whitespace lines.\n", address_file);
        } // else it's a file open error, message printed in the function
        hashset_destroy(target_address_hs);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    fprintf(stderr, "Info: Finished loading target addresses. Added %zu unique addresses to Hash Set.\n", actual_added_count);
    if (!g_debug) {
        fprintf(stderr, "Bloom Filter estimated entries: %ld, FPR: %.6f\n", estimated_entries, false_positive_rate);
        fprintf(stderr, "Hash Set unique entries: %zu\n", actual_added_count);
        fprintf(stderr, "Note: Bloom Filter is used for initial probabilistic check, Hash Set for final deterministic confirmation.\n");
    }


    // Open public key file
    FILE *pubkey_f = fopen(pubkey_file, "r");
    if (!pubkey_f) { fprintf(stderr, "Error: Cannot open public key file '%s'\n", pubkey_file); hashset_destroy(target_address_hs); bloom_free(target_address_bf); secp256k1_context_destroy(ctx); return 1; }
    fprintf(stderr, "Info: Opened public key file '%s'.\n", pubkey_file); // Corrected format string

    // Open output file if specified
    if (output_filename) {
        output_file = fopen(output_filename, "w");
        if (!output_file) { fprintf(stderr, "Error: Cannot open output file '%s'\n", output_filename); fclose(pubkey_f); hashset_destroy(target_address_hs); bloom_free(target_address_bf); secp256k1_context_destroy(ctx); return 1; }
        fprintf(stderr, "Info: Outputting results to file '%s'.\n", output_filename);
    } else { fprintf(stderr, "Info: Outputting results to stdout.\n"); }
    fprintf(stderr, "Info: Using %d worker threads.\n", num_threads);

    if (check_all_coins) fprintf(stderr, "Info: Checking ALL supported address types for each public key.\n");
    else fprintf(stderr, "Info: Checking ONLY %s address types for each public key.\n", coin_type_to_match);


    // --- Initialize Threading Resources ---
    size_t queue_capacity = 10000;
    if (queue_init(&work_queue, queue_capacity) != 0) {
        fprintf(stderr, "Error: Failed to initialize work queue.\n");
        if (output_file != stdout) fclose(output_file); // 這個內層 if 判斷是 OK 的
        fclose(pubkey_f);
        hashset_destroy(target_address_hs);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1; // 這個 return 現在明確在 if 塊內
    }
    if (pthread_mutex_init(&output_mutex, NULL) != 0) {
        fprintf(stderr, "Error: Failed to initialize output mutex.\n");
        queue_destroy(&work_queue); // queue_destroy frees items inside
        if (output_file != stdout) fclose(output_file);
        fclose(pubkey_f);
        hashset_destroy(target_address_hs);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }
     if (pthread_mutex_init(&count_mutex, NULL) != 0) {
        fprintf(stderr, "Error: Failed to initialize count mutex.\n");
        // 注意：output_mutex 可能已經初始化成功，需要在 error 時銷毀
        // 如果 output_mutex 初始化成功，應該在這裏銷毀
        pthread_mutex_destroy(&output_mutex);
        queue_destroy(&work_queue);
        if (output_file != stdout) fclose(output_file);
        fclose(pubkey_f);
        hashset_destroy(target_address_hs);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    worker_data = (worker_data_t *)malloc(num_threads * sizeof(worker_data_t));
    if (!threads || !worker_data) {
         fprintf(stderr, "Error: Failed to allocate memory for threads or worker data.\n");
         // 在這裏清理所有已成功初始化的資源
         pthread_mutex_destroy(&count_mutex); // 假設已成功
         pthread_mutex_destroy(&output_mutex); // 假設已成功
         queue_destroy(&work_queue); // 假設已成功

         if (output_file != stdout) fclose(output_file);
         fclose(pubkey_f);
         hashset_destroy(target_address_hs); // 假設已成功
         bloom_free(target_address_bf); // 假設已成功
         secp256k1_context_destroy(ctx); // 假設已成功

         free(threads); // free(NULL) 是安全的
         free(worker_data); // free(NULL) 是安全的

         return 1;
    }

    // Create worker threads
    for (int i = 0; i < num_threads; ++i) {
        worker_data[i].bf = target_address_bf;
        worker_data[i].target_address_hs = target_address_hs; // <-- Pass Hash Set pointer
        worker_data[i].coin_type_to_match = coin_type_to_match;
        worker_data[i].check_all_coins = check_all_coins;
        worker_data[i].output_file = output_file;
        worker_data[i].output_mutex = &output_mutex;
        worker_data[i].count_mutex = &count_mutex;
        worker_data[i].processed_count = &processed_count;
        worker_data[i].work_queue = &work_queue;
        worker_data[i].ctx = ctx;
        worker_data[i].debug = g_debug;

        if (pthread_create(&threads[i], NULL, worker_process_key, &worker_data[i]) != 0) {
            fprintf(stderr, "Error: Failed to create worker thread %d.\n", i);
            // Corrected misleading indentation and added cleanup
            // Signalling producer_done and broadcast wakes up already running workers
            pthread_mutex_lock(&work_queue.mutex);
            work_queue.producer_done = true; // Signal completion
            pthread_cond_broadcast(&work_queue.can_consume); // Wake up consumers
            pthread_mutex_unlock(&work_queue.mutex);

            // Join any threads that were successfully created (from index 0 to i-1)
            for (int j = 0; j < i; ++j) {
                 pthread_join(threads[j], NULL);
            }

            // Perform all necessary cleanups (assuming resources up to this point were initialized)
            pthread_mutex_destroy(&count_mutex);
            pthread_mutex_destroy(&output_mutex);
            queue_destroy(&work_queue); // queue_destroy frees items

            if (output_file != stdout) fclose(output_file);
            fclose(pubkey_f);
            hashset_destroy(target_address_hs);
            bloom_free(target_address_bf);
            secp256k1_context_destroy(ctx);

            free(threads); // threads array was allocated
            free(worker_data); // worker_data array was allocated

            return 1; // Exit main due to fatal error
        }
         if (g_debug) fprintf(stderr, "Debug: Created worker thread %d.\n", i);
    }
    fprintf(stderr, "Info: Started %d worker threads.\n", num_threads);
    
    // --- Main Thread (Producer) ---
    char line[256];
    struct timeval start_time, current_time, last_speed_time; // Corrected variable names
    long long last_speed_count = 0;

    gettimeofday(&start_time, NULL);
    last_speed_time = start_time;

    fprintf(stderr, "Info: Starting processing public keys from '%s'...\n", pubkey_file); // Corrected format string
    fflush(stderr);
    long long keys_read = 0;

    while (fgets(line, sizeof(line), pubkey_f)) {
        keys_read++;
        char *pub_hex_line = trim_whitespace(line);
        size_t hex_len = strlen(pub_hex_line);

        if (hex_len == 0) { if (g_debug) fprintf(stderr, "Debug: Skipping empty or whitespace-only public key line.\n"); continue; }

        work_item_t item;
        item.pubkey_hex = strdup(pub_hex_line);
        if (!item.pubkey_hex) { fprintf(stderr, "Error: Memory allocation failed for work item string (key: %s...). Skipping.\n", pub_hex_line); continue; }

        if (queue_enqueue(&work_queue, item) != 0) { fprintf(stderr, "Error: Failed to enqueue work item for %s... Producer stopping.\n", pub_hex_line); free(item.pubkey_hex); break; }

        pthread_mutex_lock(&count_mutex); long long current_processed = processed_count; pthread_mutex_unlock(&count_mutex);
        gettimeofday(&current_time, NULL); // Corrected variable name
        double elapsed_sec = (current_time.tv_sec - last_speed_time.tv_sec) + (current_time.tv_usec - last_speed_time.tv_usec) / 1000000.0;

        if (elapsed_sec >= 0.5) {
            long long keys_since_last = current_processed - last_speed_count;
            double speed = keys_since_last / elapsed_sec;
            fprintf(stderr, "\rProcessed: %lld keys | Speed: %.2f keys/sec%*s", current_processed, speed, 40, "");
            fflush(stderr);
            last_speed_time = current_time;
            last_speed_count = current_processed;
        }
    }

     pthread_mutex_lock(&count_mutex); long long final_processed = processed_count; pthread_mutex_unlock(&count_mutex);
     gettimeofday(&current_time, NULL); // Corrected variable name
     double final_elapsed_sec_segment = (current_time.tv_sec - last_speed_time.tv_sec) + (current_time.tv_usec - last_speed_time.tv_usec) / 1000000.0;
     if (final_elapsed_sec_segment > 0) { double final_speed_segment = (final_processed - last_speed_count) / final_elapsed_sec_segment; fprintf(stderr, "\rProcessed: %lld keys | Speed: %.2f keys/sec%*s\n", final_processed, final_speed_segment, 40, ""); }
     else { fprintf(stderr, "\rProcessed: %lld keys%*s\n", final_processed, 60, ""); }


    pthread_mutex_lock(&work_queue.mutex);
    work_queue.producer_done = true;
    pthread_cond_broadcast(&work_queue.can_consume);
    pthread_mutex_unlock(&work_queue.mutex);
    fprintf(stderr, "Info: Finished reading public key file '%s'. Total lines read: %lld. Waiting for workers to finish...\n", pubkey_file, keys_read); // Corrected format string


    // --- Wait for Workers to Finish ---
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
         if (g_debug) fprintf(stderr, "Debug: Worker thread %d joined.\n", i);
    }
    fprintf(stderr, "Info: All worker threads finished.\n");


    // --- Final Total Speed Report ---
    gettimeofday(&current_time, NULL); // Corrected variable name
    double total_elapsed_sec = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
     if (total_elapsed_sec <= 0) total_elapsed_sec = 0.001;
    double total_speed = processed_count / total_elapsed_sec;
    fprintf(stderr, "Info: Total keys processed: %lld | Total time: %.2f sec | Average speed: %.2f keys/sec\n",
            processed_count, total_elapsed_sec, total_speed);


    // --- Cleanup ---
    free(threads);
    free(worker_data);
    pthread_mutex_destroy(&count_mutex);
    pthread_mutex_destroy(&output_mutex);
    queue_destroy(&work_queue);

    if (output_file != stdout) { fclose(output_file); fprintf(stderr, "Info: Closed output file '%s'.\n", output_filename); }
    else { fprintf(stderr, "Info: Using stdout for output.\n"); }

    fclose(pubkey_f);
    fprintf(stderr, "Info: Closed public key file '%s'.\n", pubkey_file); // Corrected format string

    hashset_destroy(target_address_hs); // <-- Destroy Hash Set
    fprintf(stderr, "Info: Freed Hash Set.\n");

    bloom_free(target_address_bf);
    fprintf(stderr, "Info: Freed Bloom Filter.\n");

    secp256k1_context_destroy(ctx);
    if (g_debug) fprintf(stderr, "Debug: Destroyed secp256k1 context.\n");

    return 0;

usage_error:
    fprintf(stderr, "\nUsage: %s -i <public_key_file> -f <address_file> [-b|-e|-d|-l|-a|-z|-c|-g|-all] [-t <threads>] [-o <output_file>] [-bug]\n", argv[0]);
    fprintf(stderr, "  -i <public_key_file> : File containing public keys (one hex per line).\n");
    fprintf(stderr, "  -f <address_file>    : File containing target addresses (one per line).\n");
    fprintf(stderr, "  -b/-e/-d/-l/-a/-z/-c/-g : Specify the target coin type (required, exactly one unless using -all).\n");
    fprintf(stderr, "  -all                 : Check all supported address types for each public key (mutually exclusive with specific coin flags).\n");
    fprintf(stderr, "  -t <threads>         : Number of worker threads (default: 4).\n");
    fprintf(stderr, "  -o <output_file>     : Optional output file. Writes to stdout if not specified.\n");
    fprintf(stderr, "  -bug                 : Optional debug mode. Prints processing details and speed.\n");
    return 1;
}
