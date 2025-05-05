# Public key balance query

The program will read the file with the public key, calculate each line, generate various addresses, and quickly check and compare them with the addresses with balance in the file. If it hits, the program will output the public key that may correspond to the address with balance to the document. In simple terms, the address calculated by the public key is compared with the address with money. If the two addresses are the same, then it means that this public key has a balance and is the same public key as the address with balance.

## Features

*   Reads a list of public keys from a file.
*   Reads a list of target addresses from a file and loads them into a Bloom Filter for fast lookup.
*   Supports generating and checking addresses for multiple cryptocurrencies and address types:
    *   **BTC:** P2PKH (Compressed/Uncompressed), P2SH-P2WPKH (Compressed/Uncompressed), Bech32 P2WPKH (Compressed/Uncompressed)
    *   **ETH:** Standard (Uncompressed only, derived from uncompressed key without 0x04 prefix)
    *   **DOGE:** P2PKH (Compressed/Uncompressed)
    *   **LTC:** P2PKH (Compressed/Uncompressed)
    *   **DASH:** P2PKH (Compressed/Uncompressed)
    *   **ZEC:** Transparent P2PKH (Compressed/Uncompressed)
    *   **BCH:** CashAddr P2PKH (Compressed/Uncompressed, output *without* prefix)
    *   **BTG:** P2PKH (Compressed/Uncompressed)
*   Option to check address types for a single specific coin or all supported coins.
*   Supports multithreading to accelerate checking (`-t` parameter).
*   Can specify an output file (`-o` parameter), defaults to standard output.
*   Debug mode (`-bug` parameter) provides more detailed processing information (to stderr) and potential match address details (to output file/stdout).

## Building

The program depends on the `libsecp256k1` library. You need to install the development files for this library. On Debian/Ubuntu, you can use:

```bash
sudo apt-get update
sudo apt-get install libsecp256k1-dev
```

The libsecp256k1.a static library has been downloaded, just compile it directly, and make sure all custom .c and .h files included in the code (such as bloom.c, sha256.c, ripemd160.c, base58.c, bech32.c, keccak256.c, cashaddr.c, bloom.h, etc.) are in the same directory as main.c, and you have the libsecp256k1.a static library available (usually provided by the dev package or need to be built by yourself).

Compile the code using gcc:
```
gcc main.c sha256.c ripemd160.c base58.c bech32.c keccak256.c cashaddr.c bloom.c -O3 -march=native -o address_checker libsecp256k1.a -lm -pthread -Wall -Wextra
```

-O3 -march=native: Enables optimization and targets the native CPU architecture.

-o address_checker: Specifies the output executable name as address_checker.

libsecp256k1.a: Links the libsecp256k1 static library. Ensure the compiler can find this file.

-lm: Links the math library.

-pthread: Supports POSIX threads.

-Wall -Wextra: Enables all common and extra warnings.

Upon successful compilation, you will have an executable named address_checker.

Usage
```
./address_checker -i <public_key_file> -f <address_file> [-b|-e|-d|-l|-a|-z|-c|-g|-all] [-t <threads>] [-o <output_file>] [-bug]
```

Parameter Description:

-i <public_key_file>: Required, the public key obtained from the block, the file path containing the list of public keys to be checked (one hexadecimal string per line, 66 or 130 characters). Leading/trailing spaces will be truncated.

-f <address_file>: Required, the path to the file containing the list of target addresses (one address per line) to be downloaded from the website with extra addresses. Leading/trailing spaces will be removed.

-b | -e | -d | -l | -a | -z | -c | -g | -all: Required, specifies the coin type(s) to check.

-b: Bitcoin (BTC)

-e: Ethereum (ETH) - Note: Only checks addresses derived from uncompressed public keys.

-d: Dogecoin (DOGE)

-l: Litecoin (LTC)

-a: DASH (DASH)

-z: Zcash (ZEC) - Note: Only checks transparent addresses (t-addrs).

-c: Bitcoin Cash (BCH) - Note: Only checks CashAddr P2PKH type, output without prefix.

-g: Bitcoin Gold (BTG)

-all: Check all types of addresses, all address types supported by each public key. This option is mutually exclusive with the currency-specific option.

-t <threads>: Optional, specifies the number of worker threads to use. Defaults to 4.

-o <output_file>: Optional, writes results to the specified file. If not specified, output goes to standard output (stdout).

-bug: Optional, enables debugging mode. This is usually used to test the correctness of the program's address calculations, verifying that it calculates the correct addresses, print detailed processing information to the standard error (stderr) console or the specified document file, and include more detailed information about potential matches in the output file/stdout.

Examples:

Use 8 threads to check the public key obtained from the block in my_pubkeys.txt with the BTC address with balance downloaded from the website in target_btc_addresses.txt, and output the results to matches.txt:
```
./address_checker -i my_pubkeys.txt -f target_btc_addresses.txt -b -t 8 -o matches.txt
```

Using the default thread, outputting to stdout and enabling debug mode, check the public key in all_keys.txt against any supported coin address in all_addresses.txt, with debug printouts to the console:
```
./address_checker -i all_keys.txt -f all_addresses.txt -all -bug
```
# Input File Format

Public Key File (<public_key_file>): Each line should contain one public key as a hexadecimal string. Both compressed (66 characters) and uncompressed (130 characters) formats are supported. The program will skip lines with incorrect format or length. Leading/trailing whitespace is ignored.

Address File (<address_file>): Each line should contain one target address string. Supports Base58Check and Bech32 formats as appropriate for the chosen coin(s). Empty lines will be skipped. Leading/trailing whitespace is ignored.

# Debug mode (-bug):
Please use a few public keys for testing, otherwise it will be too confusing. In addition to the standard error output for processing details, the output file /stdout will contain a more detailed line for each public key found to be a "possible match":
```
./address_checker -i 1.txt -f 2.txt -all -bug
Debug: secp256k1 context created.
Info: Counting lines in target address file '2.txt'...
Debug: count_lines_in_file: Counted 13 lines in '2.txt'.
Info: Initializing Bloom Filter for approx 13 entries with FPR 0.000001...
Info: Bloom Filter initialized (bit_count=374, byte_count=47, hash_count=20).
Info: Loading target addresses into Bloom Filter from '2.txt'...
Debug: Finished loading addresses into bloom filter. Added 13 addresses.
Info: Finished loading target addresses into Bloom Filter.
Info: Opened public key file '1.txt'.
Info: Outputting results to stdout.
Info: Using 4 worker threads.
Info: Generating and checking ALL supported address types for each public key.
Debug: Created worker thread 0.
Debug: Created worker thread 1.
Debug: Created worker thread 2.
Debug: Created worker thread 3.
Info: Started 4 worker threads.
Info: Starting processing public keys from '1.txt'...
Processed: 0 keys | Speed: 0.00 keys/sec                                        
Info: Finished reading public key file '1.txt'. Total lines read: 1. Waiting for workers to finish...
Debug: Generated BTC: P2PKH (Compressed): 17miFNJvqmM5G4YUrS8YAfYhVHJYfejWVU
Debug: Generated BTC: P2PKH (Uncompressed): 1NosJD3YKsKjiS6TfhjRbw9dapyr7sr7Rf
Debug: Generated BTC: P2SH-P2WPKH (Compressed): 32zZkAcMJY6uUbCRAC9rKoB3dG8DQz9u33
Debug: Generated BTC: P2SH-P2WPKH (Uncompressed): 3MWDnEsjrJd5Ch6k4vnw4yy19d2E3CqoHu
Debug: Generated BTC: BECH32 (P2WPKH) (Compressed): bc1qffzh6fe2v2hzvs63tcywl2584j3grtm7quyvpr
Debug: Generated BTC: BECH32 (P2WPKH) (Uncompressed): bc1qaumu9cw6etmkxgxndcxwszvlm87ezrwnrkr8tw
Debug: Generated ETH: ETH: 0x3a4eae21ac13da97f2e8a7a33425e609510df456
Debug: Generated DOGE: P2PKH (Compressed): DBuondFa9BFMo4j5b286iRiJNR2qxHKhP5
Debug: Generated DOGE: P2PKH (Uncompressed): DSwxqTzBdHE2FSH4QHiz9hKETxi9Nac8yR
Debug: Generated LTC: P2PKH (Compressed): LRzfWackvRb8WsEe2a7qSgcThVfpkKy3aL
Debug: Generated LTC: P2PKH (Uncompressed): Lh2pZRMNQXZnyEncqqiisxDPo3M8AcpVcf
Debug: Generated DASH: P2PKH (Compressed): XhTZ5cxpoUZfR194iKSm2CEVKctEgLfd1p
Debug: Generated DASH: P2PKH (Uncompressed): XxVi8ThSHaYKsNh3Xb3eTTqRRAZY9oNP6f
Debug: Generated ZEC: P2PKH (Transparent) (Compressed): t1QeKFhj4p68frhbNnrwfJUecjwVdRwbQ4p
Debug: Generated ZEC: P2PKH (Transparent) (Uncompressed): t1fgUJYTgJC7LK59Mc8YYjkFYqVAvse8yJC
Debug: Generated BCH: CashAddr P2PKH (Compressed): qp9y2lf89f32ufjr290q3ma2s7k29qd00c5fgg6z8f
Debug: Generated BCH: CashAddr P2PKH (Uncompressed): qrhn0shpmt90wceq6dhqe6qfnlvlmygd6v7zecf269
Debug: Generated BTG: P2PKH (Compressed): GQcdfVdspcxNLXqmnNnebRtbQT6Pb3nEha
Debug: Generated BTG: P2PKH (Uncompressed): GfeniLNVJiw2nuPkbePY2hVXVzmh6CBvp1
Debug: Worker thread 0 joined.
Debug: Worker thread 1 joined.
Debug: Worker thread 2 joined.
Debug: Worker thread 3 joined.
Info: All worker threads finished.
Info: Total keys processed: 1 | Total time: 0.00 sec | Average speed: 1855.29 keys/sec
Info: Using stdout for output.
Info: Closed public key file '1.txt'.
Info: Freed Bloom Filter.
Debug: Destroyed secp256k1 context.
```

Example:
```
./address_checker -i 550001.600000.txt -f Bitcoin.txt -b -t 8 -o b.550001.600000.txt 
Info: Counting lines in target address file 'Bitcoin.txt'...
Info: Initializing Bloom Filter for approx 52986596 entries with FPR 0.000001...
Info: Bloom Filter initialized (bit_count=1523638848, byte_count=190454856, hash_count=20).
Info: Loading target addresses into Bloom Filter from 'Bitcoin.txt'...
Info: Finished loading target addresses into Bloom Filter.
Warning: Using Bloom Filter for lookup. Results may include false positives.
Estimated target addresses: 52986596, False positive rate: 0.000001
Info: Opened public key file '550001.600000.txt'.
Info: Outputting results to file 'b.550001.600000.txt'.
Info: Using 8 worker threads.
Info: Generating and checking ONLY BTC address types for each public key.
Info: Started 8 worker threads.
Info: Starting processing public keys from '550001.600000.txt'...
Processed: 135329242 keys | Speed: 237555.23 keys/sec                                        
Info: Finished reading public key file '550001.600000.txt'. Total lines read: 135339239. Waiting for workers to finish...
Info: All worker threads finished.
Info: Total keys processed: 135339239 | Total time: 570.03 sec | Average speed: 237425.48 keys/sec
Info: Closed output file 'b.550001.600000.txt'.
Info: Closed public key file '550001.600000.txt'.
Info: Freed Bloom Filter.
```
Bloom Filter False Positives: The program uses a Bloom Filter for rapid lookup of target addresses. A Bloom Filter is a probabilistic data structure and can have false positives (reporting an element exists when it doesn't). This means the list of public keys output by the program only contains potentially matching public keys. You MUST manually verify or use another tool to confirm if each output public key truly corresponds to an address in your target list. The false positive rate can be adjusted in the code (default is 0.000001).

1. Address Type Coverage: The program attempts to generate multiple possible address types (compressed/uncompressed P2PKH, P2SH, Bech32, etc., plus ETH) for each public key and checks all of them against the Bloom Filter. Therefore, a public key might be flagged as a "possible match" even if its standard address type is not in the target list, but one of its non-standard types (e.g., a P2PKH address derived from the uncompressed key) is in the target list.

2. Performance: While multithreading and Bloom Filters are used for speed, actual performance depends on your CPU cores, memory, disk I/O speed, and the size and content of the input files.

3. Dependencies: Compilation and execution require specific libraries and headers. Ensure your system environment meets these requirements.

4. CashAddr Without Prefix: For Bitcoin Cash (BCH) CashAddr, the program generates and checks the address string without the prefix (like bitcoincash:). Please ensure your target address file for BCH also does not contain these prefixes.

If you need the public key of the BTC blockchain, please go to my other library to extract the public key.

https://github.com/8891689/Bitcoin-PublicKey-Extractor

An address with a balance is required, please download it from the website below.

# Get the world's richest addresses ranking for free

http://addresses.loyce.club/

https://blockchair.com/dumps

# The public key mentioned verifies whether there is a balance.
```
gcc public.c sha256.c ripemd160.c base58.c bech32.c keccak256.c cashaddr.c -O3 -march=native -o p libsecp256k1.a
```
```
./p 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Input Public Key (Hex): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
------------------------------------------------------------------------------------
Serialized Public Key (Compressed): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Hash160 (Compressed Pubkey):        751e76e8199196d454941c45d1b3a323f1433bd6
------------------------------------------------------------------------------------
Serialized Public Key (Uncompressed): 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
Hash160 (Uncompressed Pubkey):      91b24bf9f5288532960ac687abb035127b1d28a5
------------------------------------------------------------------------------------
Generated Addresses (from this key):
------------------------------------------------------------------------------------
BTC P2PKH (Compressed Pubkey Hash): 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
BTC P2PKH (Uncompressed Pubkey Hash): 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
BTC P2SH-P2WPKH (Compressed Pubkey Hash): 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
BTC P2SH-P2WPKH (Uncompressed Pubkey Hash): 33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN
BTC BECH32 (P2WPKH) (Compressed Pubkey Hash): bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
BTC BECH32 (P2WPKH) (Uncompressed Pubkey Hash): bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h
DOGE P2PKH (Compressed Pubkey Hash): DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE
DOGE P2PKH (Uncompressed Pubkey Hash): DJRU7MLhcPwCTNRZ4e8gJzDebtG1H5M7pc
LTC P2PKH (Compressed Pubkey Hash): LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ
LTC P2PKH (Uncompressed Pubkey Hash): LYWKqJhtPeGyBAw7WC8R3F7ovxtzAiubdM
DASH P2PKH (Compressed Pubkey Hash): XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE
DASH P2PKH (Uncompressed Pubkey Hash): XoyDQM3xGhFW5JqYBwTLckjqZ67Q3jZfAL
ZEC P2PKH (Transparent) (Compressed Pubkey Hash): t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs
ZEC P2PKH (Transparent) (Uncompressed Pubkey Hash): t1X9yaRpCHJpWX1HrGUxEu39xyQinmo3Ana
BCH CashAddr P2PKH (Compressed Pubkey Hash): qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h
BCH CashAddr P2PKH (Uncompressed Pubkey Hash): qzgmyjle755g2v5kptrg02asx5f8k8fg55zdx7hd4l
BTG P2PKH (Compressed Pubkey Hash): GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5
BTG P2PKH (Uncompressed Pubkey Hash): GX8HzDj1HqeCzqYFFzoEBzPwdvKZ4H2538
ETH ETH (from Uncompressed Pubkey): 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
------------------------------------------------------------------------------------
```
# The obtained address can be searched directly in the blockchain browser. Remember to replace the address, you can view many currencies with one click.

https://privatekeys.pw/address/bitcoin/1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH

or

https://www.oklink.com/zh-hans/all-chain

# Auxiliary advanced commands Debian/Ubuntu

2. ethereum.txt Search in Documentation 100000000000000

grep -B 1 "100000000000000" ethereum.txt

3. The Merge and Remove Duplicates command merges the two files 1.txt and 2.txt into one file 1.2.txt after removing duplicates.

cat 1.txt 2.txt | sort -u > 1.2.txt 

4. Remove duplicate commands to remove redundant data in the 1.txt document, such as addresses or public keys, and make it a unique 1.2.txt

sort -u 1.txt > 1.2.txt

5. Count the number of lines in the command 1.2.txt document.

wc -l 1.2.txt

6. Extract the address and remove any extraneous values，Remove the redundant numbers after the address downloaded from the website. Usage and procedure: Input address.txt Output address.txt. The files need real names, just add a space bar.

```
gcc extract_address.c -O3 -march=native -o extract_address
```
7. Amount Classification，Remove the redundant numbers after the address downloaded from the website, usage, program Input address.txt, the file needs a real name, output a fixed name, each space key is OK. Can be set. 
```
gcc classify_balance.c -O3 -march=native -o classify_balance
```
```
#define OUTPUT_FILE_5_PLUS "balance_5_digits_or_more.txt"
#define OUTPUT_FILE_9_PLUS "balance_9_digits_or_more.txt"
```
The following is to set the number of digits for withdrawing balance, such as the default, BTC, 5 digits are addresses above 1 US dollar, 9 digits are addresses around 1BTC, divided into two types of addresses.
```
// Check if the condition of >= 5 digits is met
if (balance_length >= 5) {
// Use fprintf to write the address, tab, balance, and newline to the file
// Note: the address string is modified (tab becomes \0)
// balance_str points to the content after the tab
fprintf(output_file_5_plus, "%s\t%s\n", address, balance_str);
}

// Check if the condition of >= 9 digits is met
// If >= 9 is met, >= 5 is also met. Here is the logic of writing to two files separately.
if (balance_length >= 9) {
fprintf(output_file_9_plus, "%s\t%s\n", address, balance_str);
}
The number of digits can be set, and ETH can be more complicated.
```

8. Various addresses and hash values, as well as public key extraction commands, such as extracting only the address of the required length from the document, as well as the hash value 160, the public key, the document name in front, and the output name behind.

```
grep -o -E '1[a-zA-Z0-9]{25,34}' Bitcoin_addresses_LATEST.txt > bitcoin_addresses.txt            // For example, this command only extracts the address and length starting with 1.

grep -o -E 't[13][1-9A-HJ-NP-Za-km-z]{33,34}' blockchair_zcash_addresses_latest.tsv > zcash_addresses

grep -o -E '([LM][1-9A-HJ-NP-Za-km-z]{33}|ltc1[02-9ac-hj-np-z]{39,59})' blockchair_litecoin_addresses_latest.tsv > litecoin_addresses

grep -o -E '([DA9][1-9A-HJ-NP-Za-km-z]{25,34})' blockchair_dogecoin_addresses_latest.tsv > dogecoin_addresses

grep -o -E '([X7][1-9A-HJ-NP-Za-km-z]{33})' blockchair_dash_addresses_latest.tsv > dash_addresses

grep -o -E '([qp][0-9a-z]{42})' blockchair_bitcoin-cash_addresses_latest.tsv > cash_addresses
                                   ---------------------------------          ---------------
                                        Download document data from the website  >  Extract plain text address

grep -Eo '\b[a-fA-F0-9]{40}\b' bitcoin.160.txt > all.Bitcoin.160.txt     // This is the hash 160 of length 40 in the extracted document. Remove the redundant length and the non-conforming hash value.


grep -o -E '[0-9a-fA-F]{66}' b9b6d08d1e16.txt > 9b6d08d1e16.txt          //This is to extract the public key in the document that meets the length and prefix, and output it to a new document. Test the small data and extract it if it is suitable. If it is not suitable, ask AI to help you adjust it.

grep -o -E '0[23][0-9a-fA-F]{64}' b9b6d08d1e16.txt > 9b6d08d1e16.txt

grep -E '^[0-9a-fA-F]{66} # +' 189b3bc478.txt | grep -o -E '[0-9a-fA-F]{66}' > bc478.txt
```

# Acknowledgements

Author: 8891689

Assisted in creation: gemini ，ChatGPT 。

Utilizes the libsecp256k1 library.

Includes implementations for SHA256, RIPEMD160, Keccak256, Base58Check, Bech32, and CashAddr.


# Sponsorship
If this project is helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
This code is only for learning and understanding how it works.
Please make sure the program runs in a safe environment and comply with local laws and regulations!
The developer is not responsible for any financial losses or legal liabilities caused by the use of this code.
