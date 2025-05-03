/*Author: 8891689
 *https://github.com/8891689
 * Assist in creation ：ChatGPT / Gemini
 * Simplified version for single key lookup.
 * Compile: gcc public.c sha256.c ripemd160.c base58.c bech32.c keccak256.c cashaddr.c -O3 -march=native -o p libsecp256k1.a
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h> 
#include <string.h>
#include <ctype.h>  

// Use the official secp256k1 library header
#include <secp256k1.h>

// Include your custom headers
#include "sha256.h"    
#include "ripemd160.h" 
#include "base58.h"    
#include "bech32.h"    
#include "keccak256.h"
#include "cashaddr.h"  

/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);
// trim_whitespace is no longer needed for single argument input.

/* 地址生成函数 (Takes serialized public key bytes and debug flag - debug flag is now ignored) */
// These functions allocate memory for the address string, caller must free it.
char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);
char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug); // Legacy
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug); // CashAddr (no prefix)
char *generate_bitcoingold_address(const uint8_t *pub_bytes, size_t pub_len, bool debug);


/* 将 hex 字符串转换为二进制数据 */
// Note: This assumes `bin` buffer is large enough (e.g., 33 or 65 bytes).
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
// Note: This assumes `hex` buffer is large enough (e.g., 66 or 130 bytes + 1).
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


/* --- Implementation of Address Generation Functions --- */
// debug parameter is ignored in this simplified version but kept for function signature compatibility

char *generate_btc_p2pkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160);
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// Modified generate_btc_p2sh_p2wpkh_address to accept any pubkey length
char *generate_btc_p2sh_p2wpkh_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
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
    if (address == NULL) { return NULL; }

    if (base58check_encode(0x05, redeem_script_hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// Modified generate_btc_bech32_address to accept any pubkey length
char *generate_btc_bech32_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
   // Standard or Non-Standard: hash the input pubkey bytes
   uint8_t pubkey_hash[20];
   hash160(pub_bytes, pub_len, pubkey_hash);

   char *address = (char *)malloc(100);
   if (address == NULL) { return NULL; }

   // segwit_addr_encode expects witness version (0 for P2WPKH) and the program (hash160 result)
   // We use the hash160 of the input pubkey bytes (can be compressed or uncompressed) as the program
   // segwit_addr_encode returns 1 on success
   if (segwit_addr_encode(address, "bc", 0, pubkey_hash, 20) != 1) {
       free(address);
       return NULL;
   }
   return address;
}

char *generate_eth_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    // ETH uses uncompressed key (65 bytes with 0x04 prefix), hashes bytes 1-64
    if (pub_len != 65 || pub_bytes[0] != 0x04) return NULL;
    uint8_t keccak_hash[32];
    keccak_256(pub_bytes + 1, 64, keccak_hash); // Hash the 64 bytes (x and y coords)

    char *address = (char *)malloc(43); // 0x + 20 bytes * 2 chars/byte + null terminator
    if (!address) return NULL;
    address[0] = '0'; address[1] = 'x';
    // The last 20 bytes (160 bits) of the Keccak hash become the address
    bin2hex(keccak_hash + 12, 20, address + 2);
    return address;
}

char *generate_dogecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x1E, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_litecoin_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x30, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_dash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x4C, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_zcash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    // Zcash Transparent P2PKH uses version prefix 0x1CB8
    uint8_t zcash_version[2] = {0x1C, 0xB8};
    uint8_t payload[22]; // 2 bytes version + 20 bytes hash
    memcpy(payload, zcash_version, 2);
    memcpy(payload + 2, hash_160, 20);
    uint8_t hash1[32], hash2[32];
    sha256(payload, 22, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[26]; // 22 bytes payload + 4 bytes checksum
    memcpy(full, payload, 22);
    memcpy(full + 22, hash2, 4);
    size_t encoded_len = 100;
    if (!b58enc(address, &encoded_len, full, 26)) { free(address); return NULL; }
    return address;
}

char *generate_bitcoincash_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    // Bitcoin Cash uses version byte 0x00 for Legacy P2PKH, same as BTC
    if (base58check_encode(0x00, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// generate_bitcoincash_cashaddr returns string WITHOUT prefix
char *generate_bitcoincash_cashaddr(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20] = {0};
    hash160(pub_bytes, pub_len, hash_160);

    char hash_hex[41] = {0}; // 20 bytes * 2 chars/byte + null terminator
    bin2hex(hash_160, 20, hash_hex);

    // Allocate buffer large enough for address *with* prefix, plus some safety
    char address_with_prefix[128] = {0};

    const char *hrp_prefix = "bitcoincash";
    int cashaddr_version = 0; // 0x00 for P2PKH
    const char *cashaddr_type_str = "P2PKH"; // Not directly used by encode_cashaddr in our impl

    // Call encode_cashaddr with HRP
    if (encode_cashaddr(hrp_prefix, cashaddr_version, cashaddr_type_str, hash_hex, address_with_prefix, sizeof(address_with_prefix)) != 0) {
        return NULL; // Encoding failed
    }

    // Find the colon and get the part after it
    char *colon_pos = strchr(address_with_prefix, ':');

    if (colon_pos == NULL) {
        // Should not happen if encode_cashaddr succeeded with HRP
        return NULL;
    }

    const char *address_without_prefix_start = colon_pos + 1;
    size_t len_without_prefix = strlen(address_without_prefix_start);

    // Allocate memory for the prefix-less string to return
    char *address_to_return = (char *)malloc(len_without_prefix + 1);
    if (address_to_return == NULL) {
         return NULL; // Allocation failed
    }

    strcpy(address_to_return, address_without_prefix_start);

    return address_to_return; // Return the string without the prefix
}

char *generate_bitcoingold_address(const uint8_t *pub_bytes, size_t pub_len, bool debug) {
    (void)debug;
    if (pub_len != 33 && pub_len != 65) return NULL;
    uint8_t hash_160[20]; hash160(pub_bytes, pub_len, hash_160); char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x26, hash_160, address, 100) != 0) { free(address); return NULL; }
    return address;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <public_key_hex>\n", argv[0]);
        fprintf(stderr, "  <public_key_hex>: Compressed (66 chars) or uncompressed (130 chars) public key hex string.\n");
        return 1;
    }

    const char *pubkey_hex_input = argv[1];
    size_t hex_len = strlen(pubkey_hex_input);

    if (hex_len != 66 && hex_len != 130) {
        fprintf(stderr, "Error: Invalid public key hex length (%zu). Must be 66 (compressed) or 130 (uncompressed).\n", hex_len);
        return 1;
    }

    uint8_t pub_bin_input[65]; // Max size for uncompressed key bytes (65)
    size_t pub_bin_input_len = hex_len / 2;

    // Convert input hex to binary bytes
    if (hex2bin(pubkey_hex_input, pub_bin_input, pub_bin_input_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex format.\n");
        return 1;
    }

    // Initialize secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create secp256k1 context.\n");
        return 1;
    }

    // Parse public key bytes using libsecp256k1
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub_bin_input, pub_bin_input_len)) {
        fprintf(stderr, "Error: Failed to parse public key (not on curve?).\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    // Get standard serialized public key bytes (compressed and uncompressed)
    uint8_t pub_comp_bytes[33];
    size_t pub_comp_len = sizeof(pub_comp_bytes);
    if (!secp256k1_ec_pubkey_serialize(ctx, pub_comp_bytes, &pub_comp_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        fprintf(stderr, "Error: Failed to serialize compressed public key.\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    uint8_t pub_uncomp_bytes[65];
    size_t pub_uncomp_len = sizeof(pub_uncomp_bytes);
    if (!secp256k1_ec_pubkey_serialize(ctx, pub_uncomp_bytes, &pub_uncomp_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        fprintf(stderr, "Error: Failed to serialize uncompressed public key.\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    // Convert serialized bytes back to hex for printing
    char pub_comp_hex[67]; // 33 * 2 + 1
    bin2hex(pub_comp_bytes, pub_comp_len, pub_comp_hex);

    char pub_uncomp_hex[131]; // 65 * 2 + 1
    bin2hex(pub_uncomp_bytes, pub_uncomp_len, pub_uncomp_hex);

    // Calculate Hash160 for both compressed and uncompressed keys
    uint8_t hash160_comp[20];
    hash160(pub_comp_bytes, pub_comp_len, hash160_comp);
    char hash160_comp_hex[41]; // 20 * 2 + 1
    bin2hex(hash160_comp, 20, hash160_comp_hex);

    uint8_t hash160_uncomp[20];
    hash160(pub_uncomp_bytes, pub_uncomp_len, hash160_uncomp);
    char hash160_uncomp_hex[41]; // 20 * 2 + 1
    bin2hex(hash160_uncomp, 20, hash160_uncomp_hex);


    // --- Print Public Keys and Hash160s ---
    printf("Input Public Key (Hex): %s\n", pubkey_hex_input);
    printf("------------------------------------------------------------------------------------\n");
    printf("Serialized Public Key (Compressed): %s\n", pub_comp_hex);
    printf("Hash160 (Compressed Pubkey):        %s\n", hash160_comp_hex);
    printf("------------------------------------------------------------------------------------\n");
    printf("Serialized Public Key (Uncompressed): %s\n", pub_uncomp_hex);
    printf("Hash160 (Uncompressed Pubkey):      %s\n", hash160_uncomp_hex);
    printf("------------------------------------------------------------------------------------\n");
    printf("Generated Addresses (from this key):\n");
    printf("------------------------------------------------------------------------------------\n");


    // --- Generate and Print Addresses for All Supported Types ---
    // Define all address generation attempts
    struct {
        char* (*generator)(const uint8_t*, size_t, bool);
        const uint8_t *bytes_comp;
        size_t len_comp;
        const uint8_t *bytes_uncomp;
        size_t len_uncomp;
        const char *type_name;
        const char *coin_name;
        // Add a flag or enum if certain types strictly only apply to one key type hash (e.g., standard segwit)
        // But based on previous request, we allow hashing of either.
    } address_attempts[] = {
        // BTC Addresses
        {generate_btc_p2pkh_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "BTC"},
        {generate_btc_p2sh_p2wpkh_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2SH-P2WPKH", "BTC"}, // Non-standard from uncompressed hash
        {generate_btc_bech32_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "BECH32 (P2WPKH)", "BTC"},   // Non-standard from uncompressed hash

        // ETH Address (only from uncompressed, needs slice)
        // Special case: ETH generator takes 64 bytes *after* the 0x04 prefix
        // Will handle this specially below, not in the generic loop.

        // DOGE Addresses
        {generate_dogecoin_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "DOGE"},

        // LTC Addresses
        {generate_litecoin_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "LTC"},

        // DASH Addresses
        {generate_dash_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "DASH"},

        // ZEC Addresses (Transparent)
        {generate_zcash_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH (Transparent)", "ZEC"},

        // BCH Addresses
        //{generate_bitcoincash_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "Legacy P2PKH", "BCH"},
        {generate_bitcoincash_cashaddr, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "CashAddr P2PKH", "BCH"},

        // BTG Addresses
        {generate_bitcoingold_address, pub_comp_bytes, pub_comp_len, pub_uncomp_bytes, pub_uncomp_len, "P2PKH", "BTG"},
    };

    char *address = NULL;

    // Iterate through all address types (excluding ETH for now)
    for (size_t i = 0; i < sizeof(address_attempts) / sizeof(address_attempts[0]); ++i) {
        // Generate from Compressed Pubkey
        address = address_attempts[i].generator(address_attempts[i].bytes_comp, address_attempts[i].len_comp, false); // debug flag ignored
        if (address) {
            printf("%s %s (Compressed Pubkey Hash): %s\n", address_attempts[i].coin_name, address_attempts[i].type_name, address);
            free(address); // Free allocated string
            address = NULL;
        }

        // Generate from Uncompressed Pubkey
        // Only generate if the generator function supports uncompressed input length
        // and if the current attempt is NOT ETH (handled separately)
        if (address_attempts[i].generator != generate_eth_address) { // Exclude ETH from this generic loop
             address = address_attempts[i].generator(address_attempts[i].bytes_uncomp, address_attempts[i].len_uncomp, false); // debug flag ignored
             if (address) {
                  printf("%s %s (Uncompressed Pubkey Hash): %s\n", address_attempts[i].coin_name, address_attempts[i].type_name, address);
                  free(address); // Free allocated string
                  address = NULL;
             }
        }
    }

     // Handle ETH Address separately as it uses a slice of the uncompressed key
     address = generate_eth_address(pub_uncomp_bytes, pub_uncomp_len, false); // debug flag ignored
     if (address) {
         printf("ETH ETH (from Uncompressed Pubkey): %s\n", address);
         free(address);
         address = NULL;
     }


    printf("------------------------------------------------------------------------------------\n");

    // Cleanup
    secp256k1_context_destroy(ctx);

    return 0;
}


