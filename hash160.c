/*Author: 8891689
 *https://github.com/8891689
 * Assist in creation ：ChatGPT / Gemini
 * Simplified version for single Hash160 hex input.
 * Compile: gcc hash160.c sha256.c ripemd160.c base58.c bech32.c cashaddr.c -O3 -march=native -o h
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h> // For bool type
#include <string.h>
#include <ctype.h>   // For tolower

// Include your custom headers
#include "sha256.h"    
#include "ripemd160.h" 
#include "base58.h"    
#include "bech32.h"   
#include "cashaddr.h"  

/* 辅助函数实现 */

/* 将 hex 字符串转换为二进制数据 */
// Note: This assumes `bin` buffer is large enough (e.g., 20 bytes for Hash160).
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
// Note: This assumes `hex` buffer is large enough (e.g., 20 bytes * 2 + 1).
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

/* 計算 hash160 (RIPEMD160(SHA256(data))) */
// Still needed for P2SH-P2WPKH redeem script hashing
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
    if (hash20 == NULL || address == NULL || addr_len == 0) return -1;
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


/* --- Implementation of Address Generation Functions (from Hash160) --- */
// These functions take the 20-byte Hash160 as input and allocate memory for the address string.
// Caller must free the returned string.

char *generate_btc_p2pkh_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); // Max address length is < 100
    if (!address) return NULL;
    if (base58check_encode(0x00, hash160, address, 100) != 0) {
        free(address); return NULL;
    }
    return address;
}

char *generate_btc_p2sh_p2wpkh_address_from_hash160(const uint8_t *pubkey_hash160, size_t pubkey_hash160_len) {
    if (pubkey_hash160_len != 20 || pubkey_hash160 == NULL) return NULL;
    // Construct the Witness Program: 0x00 0x14 <pubkey_hash160> (22 bytes total)
    uint8_t redeem_script[22] = {0x00, 0x14}; // Witness version 0, push 20 bytes
    memcpy(redeem_script + 2, pubkey_hash160, 20);

    // Hash the redeem script for P2SH address
    uint8_t redeem_script_hash160[20];
    hash160(redeem_script, 22, redeem_script_hash160);

    // Encode as Base58Check with P2SH version byte 0x05
    char *address = (char *)malloc(100);
    if (!address) return NULL;

    if (base58check_encode(0x05, redeem_script_hash160, address, 100) != 0) {
        free(address); return NULL;
    }
    return address;
}

char *generate_btc_bech32_address_from_hash160(const uint8_t *pubkey_hash160, size_t pubkey_hash160_len) {
    if (pubkey_hash160_len != 20 || pubkey_hash160 == NULL) return NULL;
    char *address = (char *)malloc(100);
    if (!address) return NULL;

   // segwit_addr_encode expects witness version (0 for P2WPKH) and the program (hash160 result)
   // segwit_addr_encode returns 1 on success
   if (segwit_addr_encode(address, "bc", 0, pubkey_hash160, 20) != 1) {
       free(address); return NULL;
   }
   return address;
}

char *generate_dogecoin_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x1E, hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_litecoin_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x30, hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_dash_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x4C, hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

char *generate_zcash_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    // Zcash Transparent P2PKH uses version prefix 0x1CB8 (2 bytes)
    uint8_t zcash_version[2] = {0x1C, 0xB8};
    uint8_t payload[22]; // 2 bytes version + 20 bytes hash
    memcpy(payload, zcash_version, 2);
    memcpy(payload + 2, hash160, 20);
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

char *generate_bitcoincash_legacy_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    // Bitcoin Cash uses version byte 0x00 for Legacy P2PKH, same as BTC
    if (base58check_encode(0x00, hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}

// generate_bitcoincash_cashaddr_from_hash160 returns string WITHOUT prefix
char *generate_bitcoincash_cashaddr_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char hash_hex[41] = {0}; // 20 bytes * 2 chars/byte + null terminator
    bin2hex(hash160, 20, hash_hex);

    // Allocate buffer large enough for address *with* prefix, plus some safety
    char address_with_prefix[128] = {0};

    const char *hrp_prefix = "bitcoincash";
    int cashaddr_version = 0; // 0x00 for P2PKH
    const char *cashaddr_type_str = "P2PKH"; // Not directly used by encode_cashaddr in our impl

    // Call encode_cashaddr with HRP
    // encode_cashaddr expects hash160 as a hex string.
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

char *generate_bitcoingold_address_from_hash160(const uint8_t *hash160, size_t hash160_len) {
    if (hash160_len != 20 || hash160 == NULL) return NULL;
    char *address = (char *)malloc(100); if (!address) return NULL;
    if (base58check_encode(0x26, hash160, address, 100) != 0) { free(address); return NULL; }
    return address;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hash160_hex>\n", argv[0]);
        fprintf(stderr, "  <hash160_hex>: Hash160 hex string (40 characters).\n");
        return 1;
    }

    const char *hash160_hex_input = argv[1];
    size_t hex_len = strlen(hash160_hex_input);

    if (hex_len != 40) {
        fprintf(stderr, "Error: Invalid Hash160 hex length (%zu). Must be 40 characters.\n", hex_len);
        return 1;
    }

    uint8_t hash160_bin[20]; // Hash160 is 20 bytes
    if (hex2bin(hash160_hex_input, hash160_bin, sizeof(hash160_bin)) != 0) {
        fprintf(stderr, "Error: Invalid Hash160 hex format.\n");
        return 1;
    }

    // --- Print Input Hash160 ---
    printf("------------------------------------------------------------------------------------\n");
    printf("Input Hash160 (Hex): %s\n", hash160_hex_input);
    printf("------------------------------------------------------------------------------------\n");
    printf("Generated Addresses:\n");
    printf("------------------------------------------------------------------------------------\n");

    // --- Generate and Print Addresses for All Supported Types ---
    char *address = NULL;

    // --- BTC ---
    printf("BTC:\n");
    address = generate_btc_p2pkh_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH: %s\n", address); free(address); address = NULL; }
    address = generate_btc_p2sh_p2wpkh_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2SH-P2WPKH: %s\n", address); free(address); address = NULL; }
    address = generate_btc_bech32_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  BECH32 (P2WPKH): %s\n", address); free(address); address = NULL; }

    // --- ETH ---
    // Cannot generate ETH address from Hash160
    printf("ETH:\n");
    printf("  (Cannot derive ETH address from Hash160)\n");

    // --- DOGE ---
    printf("DOGE:\n");
    address = generate_dogecoin_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH: %s\n", address); free(address); address = NULL; }

    // --- LTC ---
    printf("LTC:\n");
    address = generate_litecoin_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH: %s\n", address); free(address); address = NULL; }

    // --- DASH ---
    printf("DASH:\n");
    address = generate_dash_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH: %s\n", address); free(address); address = NULL; }

    // --- ZEC ---
    printf("ZEC:\n");
    address = generate_zcash_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH (Transparent): %s\n", address); free(address); address = NULL; }

    // --- BCH ---
    printf("BCH:\n");
    address = generate_bitcoincash_legacy_address_from_hash160(hash160_bin, sizeof(hash160_bin)); // Legacy
    if (address) { printf("  Legacy P2PKH: %s\n", address); free(address); address = NULL; }
    address = generate_bitcoincash_cashaddr_from_hash160(hash160_bin, sizeof(hash160_bin)); // CashAddr
    if (address) { printf("  CashAddr P2PKH: %s\n", address); free(address); address = NULL; }

    // --- BTG ---
    printf("BTG:\n");
    address = generate_bitcoingold_address_from_hash160(hash160_bin, sizeof(hash160_bin));
    if (address) { printf("  P2PKH: %s\n", address); free(address); address = NULL; }

    printf("------------------------------------------------------------------------------------\n");

    // No cleanup needed for secp256k1 context as it's removed

    return 0;
}
