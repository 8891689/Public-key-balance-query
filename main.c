/*Author: 8891689
 * Assist in creation ：gemini  ,  gcc main.c sha256.c ripemd160.c base58.c bech32.c keccak256.c cashaddr.c bloom.c -O3 -march=native -o address_checker libsecp256k1.a -lm -pthread -Wall -Wextra
 */
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
#include <unistd.h>  // For sleep/usleep or other utilities if needed

// Use the official secp256k1 library header
// Ensure libsecp256k1 development files are installed (e.g., libsecp256k1-dev on Debian/Ubuntu)
#include <secp256k1.h>

// Include your custom headers
#include "bloom.h" // Assumed interface: BloomFilter*, bloom_init, bloom_add, bloom_check, bloom_free
#include "sha256.h"    // Assumed interface: SHA256_CTX, sha256_init, update, final, sha256
#include "ripemd160.h" // Assumed interface: RIPEMD160_CTX, ripemd160_init, update, final, ripemd160
#include "base58.h"    // Assumed interface: b58enc
#include "bech32.h"    // Assumed interface: segwit_addr_encode
#include "keccak256.h" // Assumed interface: keccak_256
// Assumed cashaddr interface based on previous debugging:
// int encode_cashaddr(const char *prefix, int version, const char *type_str, const char *hash160_hex, char *out_addr, size_t out_addr_len);
#include "cashaddr.h"


/* Global debug flag */
bool g_debug = false;

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
    const char *coin_type_to_match; // Will be NULL if check_all_coins is true
    bool check_all_coins; // New flag
    FILE *output_file;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *count_mutex;
    long long *processed_count; // Shared counter for total keys processed
    work_queue_t *work_queue;
    secp256k1_context *ctx; // secp256k1 context (thread-safe for verification/serialization)
    bool debug; // Pass debug flag to worker
} worker_data_t;


/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);
char *trim_whitespace(char *str);
long count_lines_in_file(const char *filename, bool debug);
int load_addresses_into_bloomfilter(const char *filename, BloomFilter *bf, bool debug);

/* 地址生成函数 (Takes serialized public key bytes) - Implementations are below main */
char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Requires compressed key
char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);     // Requires compressed key
char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);          // Requires uncompressed key, no 0x04 prefix
char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Legacy
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug); // CashAddr (no prefix)
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
        if (item.pubkey_hex) free(item.pubkey_hex); // Free any items remaining in the queue
        q->count--; // Decrement count just in case
    }
    pthread_mutex_unlock(&q->mutex);

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->can_produce);
    pthread_cond_destroy(&q->can_consume);
    free(q->items);
}

// Returns 0 on success, -1 on failure (e.g., queue destroyed or full when producer done)
int queue_enqueue(work_queue_t *q, work_item_t item) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == q->capacity && !q->producer_done) {
        pthread_cond_wait(&q->can_produce, &q->mutex);
    }
    // Check if producer was signaled done while we were waiting
    if (q->producer_done && q->count == q->capacity) {
         pthread_mutex_unlock(&q->mutex);
         return -1; // Cannot enqueue, producer finished and queue is full
    }

    q->items[q->tail] = item;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->can_consume); // Signal consumers that there is work
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Returns 0 on success, -1 if queue is empty and producer is done
int queue_dequeue(work_queue_t *q, work_item_t *item) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->producer_done) {
        pthread_cond_wait(&q->can_consume, &q->mutex);
    }
    if (q->count == 0 && q->producer_done) { // Queue is empty and producer is done
        pthread_mutex_unlock(&q->mutex);
        return -1; // No more items
    }

    *item = q->items[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_cond_signal(&q->can_produce); // Signal producers that there is space
    pthread_mutex_unlock(&q->mutex);
    return 0;
}


/* Worker Thread Function */
void *worker_process_key(void *arg) {
    worker_data_t *data = (worker_data_t *)arg;
    work_item_t item;

    while (queue_dequeue(data->work_queue, &item) == 0) {
        char *pub_hex_line = item.pubkey_hex; // Get the allocated hex string
        size_t hex_len = strlen(pub_hex_line);

        // Validate public key hex length
        if (hex_len != 66 && hex_len != 130) {
             if (data->debug) fprintf(stderr, "Debug: Skipping invalid public key hex length (%zu): %s\n", hex_len, pub_hex_line);
             free(pub_hex_line); // Free the allocated string from the queue item
             // Increment processed count even for skipped lines for reporting purposes
             pthread_mutex_lock(data->count_mutex);
             (*data->processed_count)++;
             pthread_mutex_unlock(data->count_mutex);
             continue; // Skip this item
        }

        uint8_t pub_bin_input[65];
        size_t pub_bin_input_len = hex_len / 2;

        // Convert hex to binary bytes
        if (hex2bin(pub_hex_line, pub_bin_input, pub_bin_input_len) != 0) {
            if (data->debug) fprintf(stderr, "Debug: Skipping invalid public key hex format: %s\n", pub_hex_line);
            free(pub_hex_line);
             pthread_mutex_lock(data->count_mutex);
             (*data->processed_count)++;
             pthread_mutex_unlock(data->count_mutex);
            continue; // Skip this item
        }

        // Parse public key bytes using libsecp256k1
        secp256k1_pubkey pubkey;
        // pub_bin_input_len must be 33 or 65 for parsing
        if (pub_bin_input_len != 33 && pub_bin_input_len != 65) { // Should already be covered by hex_len check above, but double check
             if (data->debug) fprintf(stderr, "Debug: Skipping pubkey hex with unexpected binary length (%zu): %s\n", pub_bin_input_len, pub_hex_line);
             free(pub_hex_line);
              pthread_mutex_lock(data->count_mutex);
              (*data->processed_count)++;
              pthread_mutex_unlock(data->count_mutex);
             continue; // Skip this item
        }
        // secp256k1_ec_pubkey_parse is thread-safe when using a shared context for VERIFY or SIGN flags.
        if (!secp256k1_ec_pubkey_parse(data->ctx, &pubkey, pub_bin_input, pub_bin_input_len)) {
            if (data->debug) fprintf(stderr, "Debug: Skipping unparseable public key (not on curve?): %s\n", pub_hex_line);
            free(pub_hex_line);
             pthread_mutex_lock(data->count_mutex);
             (*data->processed_count)++;
             pthread_mutex_unlock(data->count_mutex);
            continue; // Invalid public key
        }

        // Get standard serialized public key bytes
        // secp256k1_ec_pubkey_serialize is also thread-safe with a shared context.
        uint8_t pub_comp_bytes[33];
        size_t pub_comp_len = sizeof(pub_comp_bytes); // Expect 33
        if (!secp256k1_ec_pubkey_serialize(data->ctx, pub_comp_bytes, &pub_comp_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
             if (data->debug) fprintf(stderr, "Debug: Failed to serialize compressed public key for: %s\n", pub_hex_line);
             free(pub_hex_line);
              pthread_mutex_lock(data->count_mutex);
              (*data->processed_count)++;
              pthread_mutex_unlock(data->count_mutex);
             continue;
        }

        uint8_t pub_uncomp_bytes[65];
        size_t pub_uncomp_len = sizeof(pub_uncomp_bytes); // Expect 65
        if (!secp256k1_ec_pubkey_serialize(data->ctx, pub_uncomp_bytes, &pub_uncomp_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
             if (data->debug) fprintf(stderr, "Debug: Failed to serialize uncompressed public key for: %s\n", pub_hex_line);
             free(pub_hex_line);
              pthread_mutex_lock(data->count_mutex);
              (*data->processed_count)++;
              pthread_mutex_unlock(data->count_mutex);
             continue;
        }


        // --- Generate Addresses and Check Bloom Filter ---
        bool possibly_matched = false;
        char matched_type_name[50] = {0};
        char matched_comp_status[20] = {0};
        char *matched_address_str = NULL;

        // Define ALL address generation attempts for ALL coins AND ALL relevant compression states
        // These represent all *potential* types.
        struct {
            char* (*generator)(const uint8_t*, size_t, bool);
            const uint8_t *bytes;
            size_t len;
            const char *type_name;
            const char *comp_status; // e.g., "Compressed", "Uncompressed"
            const char *coin_internal_name; // e.g., "BTC", "ETH", "BCH"
            // const char *address_family; // Not strictly needed for this logic
        } address_attempts[] = {
            // BTC Attempts (-b or -all)
            {generate_btc_p2pkh_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "BTC"}, // Standard
            {generate_btc_p2pkh_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "BTC"}, // Standard
            {generate_btc_p2sh_p2wpkh_address, pub_comp_bytes, pub_comp_len, "P2SH-P2WPKH", "Compressed", "BTC"}, // Standard
            {generate_btc_p2sh_p2wpkh_address, pub_uncomp_bytes, pub_uncomp_len, "P2SH-P2WPKH", "Uncompressed", "BTC"}, // NON-STANDARD
            {generate_btc_bech32_address, pub_comp_bytes, pub_comp_len, "BECH32 (P2WPKH)", "Compressed", "BTC"}, // Standard
            {generate_btc_bech32_address, pub_uncomp_bytes, pub_uncomp_len, "BECH32 (P2WPKH)", "Uncompressed", "BTC"}, // NON-STANDARD

            // ETH Attempts (-e or -all) - Only one standard type
            {generate_eth_address, pub_uncomp_bytes, pub_uncomp_len, "ETH", "", "ETH"},

            // DOGE Attempts (-d or -all) - P2PKH compressed/uncompressed
            {generate_dogecoin_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "DOGE"},
            {generate_dogecoin_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "DOGE"},

            // LTC Attempts (-l or -all) - P2PKH compressed/uncompressed
            {generate_litecoin_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "LTC"},
            {generate_litecoin_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "LTC"},

            // DASH Attempts (-a or -all) - P2PKH compressed/uncompressed
            {generate_dash_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "DASH"},
            {generate_dash_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "DASH"},

            // ZEC Attempts (-z or -all) - Transparent P2PKH compressed/uncompressed
            {generate_zcash_address, pub_comp_bytes, pub_comp_len, "P2PKH (Transparent)", "Compressed", "ZEC"},
            {generate_zcash_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH (Transparent)", "Uncompressed", "ZEC"},

            // BCH Attempts (-c or -all) - Legacy P2PKH and CashAddr P2PKH (compressed/uncompressed)
            //{generate_bitcoincash_address, pub_comp_bytes, pub_comp_len, "Legacy P2PKH", "Compressed", "BCH"}, // Standard BCH Legacy
            //{generate_bitcoincash_address, pub_uncomp_bytes, pub_uncomp_len, "Legacy P2PKH", "Uncompressed", "BCH"}, // Standard BCH Legacy
            {generate_bitcoincash_cashaddr, pub_comp_bytes, pub_comp_len, "CashAddr P2PKH", "Compressed", "BCH"}, // Standard BCH CashAddr
            {generate_bitcoincash_cashaddr, pub_uncomp_bytes, pub_uncomp_len, "CashAddr P2PKH", "Uncompressed", "BCH"}, // Standard BCH CashAddr

             // BTG Attempts (-g or -all) - P2PKH compressed/uncompressed
            {generate_bitcoingold_address, pub_comp_bytes, pub_comp_len, "P2PKH", "Compressed", "BTG"},
            {generate_bitcoingold_address, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "Uncompressed", "BTG"},
        };

        // Iterate through all possible address types defined above
        for (size_t i = 0; i < sizeof(address_attempts) / sizeof(address_attempts[0]); ++i) {

            // --- LOGIC: Only process this attempt if it is for the TARGET coin type OR if checking ALL coins ---
            if (!data->check_all_coins && strcmp(address_attempts[i].coin_internal_name, data->coin_type_to_match) != 0) {
                 // If not checking all coins, and this attempt is for a different coin, skip it.
                 continue;
             }
            // --- END LOGIC ---

            // If we reach here, this attempt is either for the target coin (if specific coin selected)
            // or it's for *any* coin (if -all is selected).

            // Attempt to generate the address using the appropriate generator and key bytes.
            char *generated_address = address_attempts[i].generator(address_attempts[i].bytes, address_attempts[i].len, data->debug);

            if (generated_address) {
                 if (data->debug) {
                     // Debug print the generated address
                     const char *display_coin = address_attempts[i].coin_internal_name;
                     const char *comp_status = strlen(address_attempts[i].comp_status) > 0 ? address_attempts[i].comp_status : "";
                     const char *type_name = address_attempts[i].type_name;

                     if (strlen(comp_status) > 0) {
                         fprintf(stderr, "Debug: Generated %s: %s (%s): %s\n", display_coin, type_name, comp_status, generated_address);
                     } else {
                          fprintf(stderr, "Debug: Generated %s: %s: %s\n", display_coin, type_name, generated_address);
                     }
                 }

                 // Check Bloom Filter if the address was successfully generated
                 if (strlen(generated_address) > 0 && bloom_check(data->bf, generated_address, strlen(generated_address))) {
                     possibly_matched = true;
                     // Store details about the match
                     strncpy(matched_type_name, address_attempts[i].type_name, sizeof(matched_type_name) - 1);
                     strncpy(matched_comp_status, address_attempts[i].comp_status, sizeof(matched_comp_status) - 1);
                     matched_address_str = strdup(generated_address); // Allocate memory!
                     if (!matched_address_str) {
                          fprintf(stderr, "Error: Failed to allocate memory for matched address string for %s. Skipping match output.\n", pub_hex_line);
                          possibly_matched = false; // Clear flag if allocation failed
                     }
                     // We found a possible match for this key for *one* address type.
                     // We can stop checking other types for this key and report the match.
                     free(generated_address); // Free the temporary generated address string before breaking
                     break;
                 }

                 free(generated_address); // Free the memory for the temporary generated address string
                 generated_address = NULL;

                 // If a match was found and details stored, the break above handles exiting the loop.
            } else {
                 if (data->debug) {
                      // Debug print if an address type failed to generate
                      const char *display_coin = address_attempts[i].coin_internal_name;
                      const char *comp_status = strlen(address_attempts[i].comp_status) > 0 ? address_attempts[i].comp_status : "";
                      const char *type_name = address_attempts[i].type_name;
                       if (strlen(comp_status) > 0) {
                           fprintf(stderr, "Debug: Failed to generate %s: %s (%s) for %s\n", display_coin, type_name, comp_status, pub_hex_line);
                       } else {
                            fprintf(stderr, "Debug: Failed to generate %s: %s for %s\n", display_coin, type_name, pub_hex_line);
                       }
                 }
            } // End of if (generated_address) else
        } // End of address_attempts loop

        // --- Output Match if Found ---
        if (possibly_matched) {
            pthread_mutex_lock(data->output_mutex);
            if (data->debug) {
                 // Debug format (to output file): 公鑰 匹配的地址類型 (壓縮狀態): 地址 -> [POSSIBLE MATCH]
                 fprintf(data->output_file, "%s %s (%s): %s -> [POSSIBLE MATCH]\n",
                         pub_hex_line, matched_type_name, matched_comp_status, matched_address_str ? matched_address_str : "N/A");
            } else {
                 // Non-debug format (to output file): ONLY 公鑰
                 fprintf(data->output_file, "%s\n", pub_hex_line);
            }
            fflush(data->output_file);
            pthread_mutex_unlock(data->output_mutex);

            if (data->debug) fprintf(stderr, "Debug: Possible match found for %s\n", pub_hex_line);
        }

        // --- Cleanup for this work item ---
        if (matched_address_str) {
            free(matched_address_str);
        }

        // Increment processed count and Free original item memory
        pthread_mutex_lock(data->count_mutex);
        (*data->processed_count)++;
        pthread_mutex_unlock(data->count_mutex);
        free(pub_hex_line);

    } // End of while queue_dequeue loop

    return NULL;
}

/* 將 hex 字符串转换为二进制数据 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || hex_len % 2 != 0) return -1;
    if (bin_len < hex_len / 2) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 将二进制数据转换为 hex 字符串 */
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

/* 計算 hash160 (RIPEMD160(SHA256(data))) */
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

/* 根据版本字节和 20 字节数据生成 Base58Check 地址 */
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);
    uint8_t hash1[32], hash2[32];
    sha256(payload, 21, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);
    size_t encoded_len = addr_len;
    if (!b58enc(address, &encoded_len, full, 25)) return -1;
    return 0;
}

/* 移除字符串前導和後繼的空白字符 */
char *trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

/* 計算文件中的行數 */
long count_lines_in_file(const char *filename, bool debug) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        if (debug) fprintf(stderr, "Debug: count_lines_in_file: Cannot open file '%s'\n", filename);
        return -1;
    }

    long count = 0;
    char buffer[8192];
    size_t bytes_read;
    bool last_char_newline = true;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < bytes_read; ++i) {
            if (buffer[i] == '\n') {
                count++;
                last_char_newline = true;
            } else {
                last_char_newline = false;
            }
        }
    }

    // Handle case where file doesn't end with a newline
    if (!last_char_newline && count > 0) { // count > 0 handles empty file case
        count++;
    }
    // If the file is not empty but has no newlines, count is 0, bytes_read was > 0. Need to count it.
     if (count == 0 && bytes_read > 0) {
         count++;
     }


    fclose(f);
    if (debug) fprintf(stderr, "Debug: count_lines_in_file: Counted %ld lines in '%s'.\n", count, filename);
    return count;
}

/* 從文件讀取地址並載入到布隆過濾器 */
int load_addresses_into_bloomfilter(const char *filename, BloomFilter *bf, bool debug) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        // Error message already printed in main caller
        return -1;
    }

    char line[256];
    size_t addresses_added = 0;
    while (fgets(line, sizeof(line), f)) {
        char *trimmed_line = trim_whitespace(line);
        if (strlen(trimmed_line) > 0) {
             bloom_add(bf, trimmed_line, strlen(trimmed_line));
             addresses_added++;
        }
    }

    fclose(f);
    // Moved standard output for this function caller
    if (debug) fprintf(stderr, "Debug: Finished loading addresses into bloom filter. Added %zu addresses.\n", addresses_added);

    return (addresses_added > 0) ? 0 : -1; // Return -1 if no addresses were added
}


/* --- Implementation of Address Generation Functions --- */
// Adding (void)debug; to suppress unused parameter warnings if needed by -Wextra

char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// Modified generate_btc_p2sh_p2wpkh_address to accept any pubkey length
char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    // Standard or Non-Standard: hash the input pubkey bytes
    uint8_t pubkey_hash[20];
    hash160(pub_bytes, pub_len, pubkey_hash);

    // Construct the Witness Program: 0x00 0x14 <hash160>
    uint8_t redeem_script[22] = {0x00, 0x14}; // Witness version 0, push 20 bytes
    memcpy(redeem_script + 2, pubkey_hash, 20); // Use the hash160 of the input pubkey here

    // Hash the redeem script for P2SH address
    uint8_t redeem_script_hash160[20];
    hash160(redeem_script, 22, redeem_script_hash160);

    // Encode as Base58Check with P2SH version byte 0x05
    char *address = (char *)malloc(100);
    if (address == NULL) { /* ... error handling ... */ return NULL; }

    if (base58check_encode(0x05, redeem_script_hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// Modified generate_btc_bech32_address to accept any pubkey length
char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
   // Standard or Non-Standard: hash the input pubkey bytes
   uint8_t pubkey_hash[20];
   hash160(pub_bytes, pub_len, pubkey_hash);

   char *address = (char *)malloc(100);
   if (address == NULL) { /* ... error handling ... */ return NULL; }

   // segwit_addr_encode expects witness version (0 for P2WPKH) and the program (hash160 result)
   // We use the hash160 of the input pubkey bytes (can be compressed or uncompressed) as the program
   // segwit_addr_encode returns 1 on success
   if (segwit_addr_encode(address, "bc", 0, pubkey_hash, 20) != 1) {
       free(address);
       if (debug) fprintf(stderr, "Debug: generate_btc_bech32_address: segwit_addr_encode failed.\n"); // Keep debug print if needed
       return NULL;
   }
   return address;
}

char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 65 || pub_bytes[0] != 0x04) return NULL; // ETH uses uncompressed key without 0x04 prefix for hashing
    uint8_t keccak_hash[32];
    keccak_256(pub_bytes + 1, 64, keccak_hash); // Hash the 64 bytes (x and y coords)

    char *address = (char *)malloc(43); // 0x + 20 bytes * 2 chars/byte + null terminator
    if (!address) return NULL;
    address[0] = '0'; address[1] = 'x';
    // The last 20 bytes of the Keccak hash become the address
    bin2hex(keccak_hash + 12, 20, address + 2);
    return address;
}


char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x1E, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];
hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x30, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];
hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x4C, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20];
hash160(pub_bytes, pub_len, hash_160);char *address = (char *)malloc(100); if (!address) return NULL;
    uint8_t zcash_version[2] = {0x1C, 0xB8}; uint8_t payload[22]; memcpy(payload, zcash_version, 2); memcpy(payload + 2, hash_160, 20);
    uint8_t hash1[32], hash2[32]; sha256(payload, 22, hash1); sha256(hash1, 32, hash2);
    uint8_t full[26]; memcpy(full, payload, 22); memcpy(full + 22, hash2, 4);
    size_t encoded_len = 100;
    if (!b58enc(address, &encoded_len, full, 26)) { free(address); return NULL; }
    return address;
}

char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    // Bitcoin Cash uses version byte 0x00 for Legacy P2PKH, same as BTC
    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// generate_bitcoincash_cashaddr returns string WITHOUT prefix, as requested
// Assumes encode_cashaddr signature: int encode_cashaddr(const char *prefix, int version, const char *type_str, const char *hash160_hex, char *out_addr, size_t out_addr_len);
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
     // (void)debug; // Suppress unused parameter warning
     if (pub_len != 33 && pub_len != 65) {
         if (debug) fprintf(stderr, "Debug: generate_bitcoincash_cashaddr: Invalid pubkey byte length %zu.\n", pub_len);
         return NULL;
     }
    uint8_t hash_160[20] = {0};
    hash160(pub_bytes, pub_len, hash_160);

    char hash_hex[41] = {0}; // 20 bytes * 2 chars/byte + null terminator
    bin2hex(hash_160, 20, hash_hex);

    // Allocate buffer large enough for address *with* prefix
    // Max CashAddr with HRP is around 50 chars. 128 is safe.
    char address_with_prefix[128] = {0};

    const char *hrp_prefix = "bitcoincash";
    int cashaddr_version = 0; // 0x00 for P2PKH
    const char *cashaddr_type_str = "P2PKH"; // This string isn't used by encode_cashaddr directly, but useful for function interface consistency

    // Call encode_cashaddr with HRP
    // Note: encode_cashaddr might actually expect the raw hash bytes or a different representation.
    // Based on the assumed interface `const char *hash160_hex`, it expects hex.
    if (encode_cashaddr(hrp_prefix, cashaddr_version, cashaddr_type_str, hash_hex, address_with_prefix, sizeof(address_with_prefix)) != 0) {
        if (debug) fprintf(stderr, "Debug: Encoding Bitcoin Cash CashAddr failed for hex: %s\n", hash_hex);
        return NULL;
    }

    // Find the colon and get the part after it
    char *colon_pos = strchr(address_with_prefix, ':');

    if (colon_pos == NULL) {
        // Should not happen if encode_cashaddr succeeded with a non-NULL hrp and the implementation is correct
        if (debug) fprintf(stderr, "Debug: Generated CashAddr with HRP but no colon found: '%s' for hex %s\n", address_with_prefix, hash_hex);
        return NULL;
    }

    const char *address_without_prefix_start = colon_pos + 1;
    size_t len_without_prefix = strlen(address_without_prefix_start);

    // Allocate memory for the prefix-less string to return
    char *address_to_return = (char *)malloc(len_without_prefix + 1);
    if (address_to_return == NULL) {
         // No need to print stderr here, caller handles NULL return
         return NULL;
    }

    strcpy(address_to_return, address_without_prefix_start);

    return address_to_return; // Return the string without the prefix
}


char *generate_bitcoingold_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug; // Suppress unused parameter warning
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x26, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}


int main(int argc, char **argv) {
    const char *pubkey_file = NULL;
    const char *address_file = NULL;
    const char *coin_type_to_match = NULL; // Will be NULL if check_all_coins is true
    bool check_all_coins = false; // New flag
    const char *output_filename = NULL;
    int num_threads = 4; // Default thread count
    FILE *output_file = stdout; // Default output to stdout
    secp256k1_context *ctx = NULL;

    // Threading resources
    pthread_t *threads = NULL;
    worker_data_t *worker_data = NULL;
    work_queue_t work_queue;
    pthread_mutex_t output_mutex;
    pthread_mutex_t count_mutex;
    long long processed_count = 0; // Shared counter for total keys processed

    // --- Command Line Argument Parsing ---
    // Usage: %s -i <public_key_file> -f <address_file> [-b|-e|-d|-l|-a|-z|-c|-g|-all] [-t <threads>] [-o <output_file>] [-bug]\n
    bool coin_flag_found = false;
    bool all_flag_found = false; // Track if -all was used
    bool input_file_found = false;
    bool address_file_found = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) { pubkey_file = argv[++i]; input_file_found = true; }
            else { fprintf(stderr, "Error: -i requires a public key file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) { address_file = argv[++i]; address_file_found = true; }
            else { fprintf(stderr, "Error: -f requires an address file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-t") == 0) {
             if (i + 1 < argc) {
                 num_threads = atoi(argv[++i]);
                 if (num_threads <= 0) { fprintf(stderr, "Error: Number of threads must be a positive integer.\n"); return 1; }
             } else {
                 fprintf(stderr, "Error: -t requires a number of threads.\n"); goto usage_error;
             }
        }
        else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) { output_filename = argv[++i]; }
            else { fprintf(stderr, "Error: -o requires an output file name.\n"); goto usage_error; }
        } else if (strcmp(argv[i], "-bug") == 0) { g_debug = true; }
        // Coin type flags
        else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-d") == 0 ||
                 strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-z") == 0 ||
                 strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-g") == 0) {
             if (coin_flag_found || all_flag_found) { fprintf(stderr, "Error: Only one coin type flag (-b, -e, etc.) or -all is allowed.\n"); return 1; }
             coin_flag_found = true;
             // Set coin_type_to_match based on the flag
             if (strcmp(argv[i], "-b") == 0) coin_type_to_match = "BTC";
             else if (strcmp(argv[i], "-e") == 0) coin_type_to_match = "ETH";
             else if (strcmp(argv[i], "-d") == 0) coin_type_to_match = "DOGE";
             else if (strcmp(argv[i], "-l") == 0) coin_type_to_match = "LTC";
             else if (strcmp(argv[i], "-a") == 0) coin_type_to_match = "DASH";
             else if (strcmp(argv[i], "-z") == 0) coin_type_to_match = "ZEC";
             else if (strcmp(argv[i], "-c") == 0) coin_type_to_match = "BCH";
             else if (strcmp(argv[i], "-g") == 0) coin_type_to_match = "BTG";
        } else if (strcmp(argv[i], "-all") == 0) {
             if (coin_flag_found || all_flag_found) { fprintf(stderr, "Error: Only one coin type flag (-b, -e, etc.) or -all is allowed.\n"); return 1; }
             all_flag_found = true;
             check_all_coins = true; // Enable the 'check all' mode
        }
        else { fprintf(stderr, "Error: Unknown argument '%s'.\n", argv[i]); goto usage_error; }
    }

    // Validate required arguments
    if (!input_file_found || !address_file_found || (!coin_flag_found && !all_flag_found) ) {
        fprintf(stderr, "Error: Missing required arguments (-i, -f, and one coin type flag or -all).\n");
        goto usage_error;
    }

    // --- Initialize secp256k1 context ---
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create secp256k1 context.\n");
        return 1;
    }
    if (g_debug) fprintf(stderr, "Debug: secp256k1 context created.\n");


    // --- Bloom Filter Initialization ---
    fprintf(stderr, "Info: Counting lines in target address file '%s'...\n", address_file);
    long estimated_entries = count_lines_in_file(address_file, g_debug);
    if (estimated_entries <= 0) {
        fprintf(stderr, "Error: Could not count lines or found no valid entries in address file '%s'.\n", address_file);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    // Re-count lines to be sure after trim_whitespace logic
    // This is a bit redundant but safer if trim logic is complex or file format is weird.
    // Let's trust the load function to report how many it *actually* added.
    double false_positive_rate = 0.000001; // 1 in a million
    fprintf(stderr, "Info: Initializing Bloom Filter for approx %ld entries with FPR %.6f...\n", estimated_entries, false_positive_rate);
    BloomFilter *target_address_bf = bloom_init((uint64_t)estimated_entries, false_positive_rate);
    if (!target_address_bf) {
        fprintf(stderr, "Error: Failed to initialize Bloom Filter.\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    fprintf(stderr, "Info: Bloom Filter initialized (bit_count=%" PRIu64 ", byte_count=%" PRIu64 ", hash_count=%" PRIu64 ").\n",
            target_address_bf->bit_count, target_address_bf->byte_count, target_address_bf->hash_count);

    // Load target addresses into Bloom Filter
    fprintf(stderr, "Info: Loading target addresses into Bloom Filter from '%s'...\n", address_file);
    if (load_addresses_into_bloomfilter(address_file, target_address_bf, g_debug) != 0) {
        fprintf(stderr, "Error: Failed to load target addresses into Bloom Filter or file was empty/invalid.\n");
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    fprintf(stderr, "Info: Finished loading target addresses into Bloom Filter.\n");
    if (!g_debug) { // Standard warning about false positives (only if not in debug mode)
        fprintf(stderr, "Warning: Using Bloom Filter for lookup. Results may include false positives.\n");
        fprintf(stderr, "Estimated target addresses: %ld, False positive rate: %.6f\n", estimated_entries, false_positive_rate);
    }


    // Open public key file
    FILE *pubkey_f = fopen(pubkey_file, "r");
    if (!pubkey_f) {
        fprintf(stderr, "Error: Cannot open public key file '%s'\n", pubkey_file);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    fprintf(stderr, "Info: Opened public key file '%s'.\n", pubkey_file);

    // Open output file if specified
    if (output_filename) {
        output_file = fopen(output_filename, "w");
        if (!output_file) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", output_filename);
            fclose(pubkey_f);
            bloom_free(target_address_bf);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        fprintf(stderr, "Info: Outputting results to file '%s'.\n", output_filename);
    } else {
         fprintf(stderr, "Info: Outputting results to stdout.\n");
    }
    fprintf(stderr, "Info: Using %d worker threads.\n", num_threads);

    if (check_all_coins) {
        fprintf(stderr, "Info: Generating and checking ALL supported address types for each public key.\n");
    } else {
        fprintf(stderr, "Info: Generating and checking ONLY %s address types for each public key.\n", coin_type_to_match);
    }


    // --- Initialize Threading Resources ---
    // Choose a reasonable queue capacity, e.g., buffer a few thousand keys
    size_t queue_capacity = 10000; // Buffer up to 10,000 keys
    if (queue_init(&work_queue, queue_capacity) != 0) {
        fprintf(stderr, "Error: Failed to initialize work queue.\n");
        if (output_file != stdout) fclose(output_file);
        fclose(pubkey_f);
        bloom_free(target_address_bf);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    if (pthread_mutex_init(&output_mutex, NULL) != 0) {
         fprintf(stderr, "Error: Failed to initialize output mutex.\n");
         queue_destroy(&work_queue);
         if (output_file != stdout) fclose(output_file);
         fclose(pubkey_f);
         bloom_free(target_address_bf);
         secp256k1_context_destroy(ctx);
         return 1;
    }
     if (pthread_mutex_init(&count_mutex, NULL) != 0) {
         fprintf(stderr, "Error: Failed to initialize count mutex.\n");
         pthread_mutex_destroy(&output_mutex);
         queue_destroy(&work_queue);
         if (output_file != stdout) fclose(output_file);
         fclose(pubkey_f);
         bloom_free(target_address_bf);
         secp256k1_context_destroy(ctx);
         return 1;
    }

    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    worker_data = (worker_data_t *)malloc(num_threads * sizeof(worker_data_t));
    if (!threads || !worker_data) {
         fprintf(stderr, "Error: Failed to allocate memory for threads or worker data.\n");
         pthread_mutex_destroy(&count_mutex);
         pthread_mutex_destroy(&output_mutex);
         queue_destroy(&work_queue);
         if (output_file != stdout) fclose(output_file);
         fclose(pubkey_f);
         bloom_free(target_address_bf);
         secp256k1_context_destroy(ctx);
         free(threads); free(worker_data); // It's safe to free NULL pointers
         return 1;
    }

    // Create worker threads
    for (int i = 0; i < num_threads; ++i) {
        worker_data[i].bf = target_address_bf;
        worker_data[i].coin_type_to_match = coin_type_to_match; // Pass the specific coin type or NULL
        worker_data[i].check_all_coins = check_all_coins; // Pass the new flag
        worker_data[i].output_file = output_file;
        worker_data[i].output_mutex = &output_mutex;
        worker_data[i].count_mutex = &count_mutex;
        worker_data[i].processed_count = &processed_count;
        worker_data[i].work_queue = &work_queue;
        worker_data[i].ctx = ctx;
        worker_data[i].debug = g_debug;

        if (pthread_create(&threads[i], NULL, worker_process_key, &worker_data[i]) != 0) {
            fprintf(stderr, "Error: Failed to create worker thread %d.\n", i);
            // Clean up already created threads and resources
            // Signal producer done BEFORE joining to ensure waiting threads exit their dequeue call
            pthread_mutex_lock(&work_queue.mutex);
            work_queue.producer_done = true; // Signal completion
            pthread_cond_broadcast(&work_queue.can_consume); // Wake up consumers
            pthread_mutex_unlock(&work_queue.mutex);

            for (int j = 0; j < i; ++j) {
                // No need to cancel explicitly if producer_done logic is correct, just join
                 pthread_join(threads[j], NULL);
            }

            pthread_mutex_destroy(&count_mutex);
            pthread_mutex_destroy(&output_mutex);
            queue_destroy(&work_queue);
            if (output_file != stdout) fclose(output_file);
            fclose(pubkey_f);
            bloom_free(target_address_bf);
            secp256k1_context_destroy(ctx);
            free(threads); free(worker_data);
            return 1;
        }
         if (g_debug) fprintf(stderr, "Debug: Created worker thread %d.\n", i);
    }
    fprintf(stderr, "Info: Started %d worker threads.\n", num_threads);


    // --- Main Thread (Producer) ---
    char line[256]; // Buffer for reading public key lines
    struct timeval start_time, current_time, last_speed_time;
    long long last_speed_count = 0;

    gettimeofday(&start_time, NULL);
    last_speed_time = start_time;

    fprintf(stderr, "Info: Starting processing public keys from '%s'...\n", pubkey_file);
    fflush(stderr);

    long long keys_read = 0; // Counter for lines read by the producer

    while (fgets(line, sizeof(line), pubkey_f)) {
        keys_read++;
        char *pub_hex_line = trim_whitespace(line);
        size_t hex_len = strlen(pub_hex_line);

        if (hex_len == 0) continue; // Skip empty lines

        // Create a work item (dynamically allocate string)
        work_item_t item;
        item.pubkey_hex = strdup(pub_hex_line); // strdup allocates memory and copies the string
        if (!item.pubkey_hex) {
             fprintf(stderr, "Error: Memory allocation failed for work item string (key: %s...). Skipping.\n", pub_hex_line);
             // Decide if we should continue or exit. Skipping is safer than crashing.
             // If we skip, keys_read will count it, but processed_count won't. That's okay.
             continue;
        }

        // Enqueue the work item - will block if queue is full
        if (queue_enqueue(&work_queue, item) != 0) {
            // This should only return -1 if producer_done is already true (unexpected for the producer)
            fprintf(stderr, "Error: Failed to enqueue work item for %s... Producer stopping.\n", pub_hex_line);
             free(item.pubkey_hex); // Free the item if enqueue fails
             break; // Exit producer loop on enqueue failure
        }

        // --- Speed Calculation and Display ---
        // Read shared processed_count for accurate speed
        pthread_mutex_lock(&count_mutex);
        long long current_processed = processed_count;
        pthread_mutex_unlock(&count_mutex);

        gettimeofday(&current_time, NULL);
        double elapsed_sec = (current_time.tv_sec - last_speed_time.tv_sec) + (current_time.tv_usec - last_speed_time.tv_usec) / 1000000.0;

        if (elapsed_sec >= 0.5) { // Update speed every 0.5 seconds or so
            long long keys_since_last = current_processed - last_speed_count;
            double speed = keys_since_last / elapsed_sec;
            // Print speed to stderr with carriage return for auto-scrolling
            // Use a fixed width or padding to clear the previous line
            fprintf(stderr, "\rProcessed: %lld keys | Speed: %.2f keys/sec%*s", current_processed, speed, 40, ""); // Pad with spaces
            fflush(stderr); // Ensure it updates on the terminal
            last_speed_time = current_time;
            last_speed_count = current_processed;
        }
    }

    // --- Signal Workers That Producer is Done ---
    // Ensure we print the final speed update before the "Finished reading" message
     pthread_mutex_lock(&count_mutex);
     long long final_processed = processed_count;
     pthread_mutex_unlock(&count_mutex);
     gettimeofday(&current_time, NULL);
     double final_elapsed_sec_segment = (current_time.tv_sec - last_speed_time.tv_sec) + (current_time.tv_usec - last_speed_time.tv_usec) / 1000000.0;
      if (final_elapsed_sec_segment > 0) { // Avoid division by zero if last update was very recent
          double final_speed_segment = (final_processed - last_speed_count) / final_elapsed_sec_segment;
          fprintf(stderr, "\rProcessed: %lld keys | Speed: %.2f keys/sec%*s\n", final_processed, final_speed_segment, 40, ""); // Print last update with newline
      } else { // If no time elapsed since last update, just print total processed
           fprintf(stderr, "\rProcessed: %lld keys%*s\n", final_processed, 60, ""); // Print total processed with newline
      }


    pthread_mutex_lock(&work_queue.mutex);
    work_queue.producer_done = true; // Set the flag
    pthread_cond_broadcast(&work_queue.can_consume); // Wake up all waiting consumers
    pthread_mutex_unlock(&work_queue.mutex);
    fprintf(stderr, "Info: Finished reading public key file '%s'. Total lines read: %lld. Waiting for workers to finish...\n", pubkey_file, keys_read);


    // --- Wait for Workers to Finish ---
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
         if (g_debug) fprintf(stderr, "Debug: Worker thread %d joined.\n", i);
    }
    fprintf(stderr, "Info: All worker threads finished.\n");


    // --- Final Total Speed Report ---
    gettimeofday(&current_time, NULL);
    double total_elapsed_sec = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
     if (total_elapsed_sec <= 0) total_elapsed_sec = 0.001; // Avoid division by zero if execution is extremely fast
    double total_speed = processed_count / total_elapsed_sec;
    fprintf(stderr, "Info: Total keys processed: %lld | Total time: %.2f sec | Average speed: %.2f keys/sec\n",
            processed_count, total_elapsed_sec, total_speed);


    // --- Cleanup ---
    free(threads);
    free(worker_data);
    pthread_mutex_destroy(&count_mutex);
    pthread_mutex_destroy(&output_mutex);
    queue_destroy(&work_queue); // Ensure any remaining items (e.g., due to enqueue failure) are freed

    if (output_file != stdout) {
        fclose(output_file);
        fprintf(stderr, "Info: Closed output file '%s'.\n", output_filename);
    } else {
         fprintf(stderr, "Info: Using stdout for output.\n");
    }

    fclose(pubkey_f);
    fprintf(stderr, "Info: Closed public key file '%s'.\n", pubkey_file);

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
