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

Ensure all custom .c and .h files included in the code (like bloom.c, sha256.c, ripemd160.c, base58.c, bech32.c, keccak256.c, cashaddr.c, bloom.h, etc.) are in the same directory as main.c, and that you have the libsecp256k1.a static library available (usually provided by the dev package or requires building yourself).

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

-i <public_key_file>: Required, path to the file containing the list of public keys to check (one hex string per line, 66 or 130 characters). Leading/trailing whitespace will be trimmed.

-f <address_file>: Required, path to the file containing the list of target addresses (one address per line). Leading/trailing whitespace will be trimmed.

-b | -e | -d | -l | -a | -z | -c | -g | -all: Required, specifies the coin type(s) to check.

-b: Bitcoin (BTC)

-e: Ethereum (ETH) - Note: Only checks addresses derived from uncompressed public keys.

-d: Dogecoin (DOGE)

-l: Litecoin (LTC)

-a: DASH (DASH)

-z: Zcash (ZEC) - Note: Only checks transparent addresses (t-addrs).

-c: Bitcoin Cash (BCH) - Note: Only checks CashAddr P2PKH type, output without prefix.

-g: Bitcoin Gold (BTG)

-all: Check all supported address types for each public key. This option is mutually exclusive with specific coin options.

-t <threads>: Optional, specifies the number of worker threads to use. Defaults to 4.

-o <output_file>: Optional, writes results to the specified file. If not specified, output goes to standard output (stdout).

-bug: Optional, enables debug mode. Prints detailed processing information to standard error (stderr) and includes more details about potential matches in the output file/stdout.

Examples:

Check public keys in my_pubkeys.txt against target BTC addresses in target_btc_addresses.txt, using 8 threads, outputting results to matches.txt:
```
./address_checker -i my_pubkeys.txt -f target_btc_addresses.txt -b -t 8 -o matches.txt
```

Check public keys in all_keys.txt against any supported coin addresses in all_addresses.txt, using default threads, outputting to stdout, and enabling debug mode:
```
./address_checker -i all_keys.txt -f all_addresses.txt -all -bug
```
Input File Format

Public Key File (<public_key_file>): Each line should contain one public key as a hexadecimal string. Both compressed (66 characters) and uncompressed (130 characters) formats are supported. The program will skip lines with incorrect format or length. Leading/trailing whitespace is ignored.

Address File (<address_file>): Each line should contain one target address string. Supports Base58Check and Bech32 formats as appropriate for the chosen coin(s). Empty lines will be skipped. Leading/trailing whitespace is ignored.

Output Format

Non-Debug Mode (Default):
If a public key generates an address that is found in the target address list (via Bloom Filter check), the public key's hexadecimal string will be printed on a single line.

02...
03...
04...

Debug Mode (-bug):
In addition to standard error output for processing details, for each public key found as a "possible match", the output file/stdout will contain a more detailed line:

<Public Key Hex String> <Matched Address Type> (<Compression Status>): <Generated Matched Address> -> [POSSIBLE MATCH]

Example:

03... BTC P2PKH (Compressed): 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa -> [POSSIBLE MATCH]
04... ETH (): 0xAb5801a7D3993597AEd9aB6DaaFBC49adBaAaE9 -> [POSSIBLE MATCH]

Bloom Filter False Positives: The program uses a Bloom Filter for rapid lookup of target addresses. A Bloom Filter is a probabilistic data structure and can have false positives (reporting an element exists when it doesn't). This means the list of public keys output by the program only contains potentially matching public keys. You MUST manually verify or use another tool to confirm if each output public key truly corresponds to an address in your target list. The false positive rate can be adjusted in the code (default is 0.000001).

1. Address Type Coverage: The program attempts to generate multiple possible address types (compressed/uncompressed P2PKH, P2SH, Bech32, etc., plus ETH) for each public key and checks all of them against the Bloom Filter. Therefore, a public key might be flagged as a "possible match" even if its standard address type is not in the target list, but one of its non-standard types (e.g., a P2PKH address derived from the uncompressed key) is in the target list.

2. Performance: While multithreading and Bloom Filters are used for speed, actual performance depends on your CPU cores, memory, disk I/O speed, and the size and content of the input files.

3. Dependencies: Compilation and execution require specific libraries and headers. Ensure your system environment meets these requirements.

4. CashAddr Without Prefix: For Bitcoin Cash (BCH) CashAddr, the program generates and checks the address string without the prefix (like bitcoincash:). Please ensure your target address file for BCH also does not contain these prefixes.

# Acknowledgements

Author: 8891689

Assisted in creation: gemini ，ChatGPT 。

Utilizes the libsecp256k1 library.

Includes implementations for SHA256, RIPEMD160, Keccak256, Base58Check, Bech32, and CashAddr.


# Sponsorship
If this project is helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

# 📜 Disclaimer
This code is only for learning and understanding how it works.
Please make sure the program runs in a safe environment and comply with local laws and regulations!
The developer is not responsible for any financial losses or legal liabilities caused by the use of this code.

