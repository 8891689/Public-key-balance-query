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

And make sure all custom .c and .h files included in your code (such as bloom.c, sha256.c, ripemd160.c, base58.c, bech32.c, keccak256.c, cashaddr.c, bloom.h, etc.) are in the same directory as main.c, and that the libsecp256k1.a static library is available (usually provided by the dev package or needs to be built yourself).

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

-i <public_key_file>: Required, public key obtained from the block, file path containing the list of public keys to be checked (one hex string per line, 66 or 130 characters). Enter the name directly under the directory. Leading/trailing spaces will be truncated.

-f <address_file>: Required, specifies the name of the target address list (one address per line with a dollar amount) to be downloaded from the website. Leading/trailing spaces will be removed.

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

-x                   : Optional. If present, output only the matched public key. Otherwise, output public key, matched address, and balance.

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

Address file (<address_file>): Each line should contain the destination address followed by the amount value. Supports Base58Check and Bech32 formats (depending on the selected token). Empty lines will be skipped. Leading/trailing spaces will be ignored.

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
1. -i The input is a standard public key, which can be compressed or uncompressed.

```
0290a2f9989d3ee835d80f6acff19fc5c2adc01caa693d4f54b84c1508c1b0d86f
027a4534be73c419f15c78ec292fcd393ce9315489a57a26da9b55e4d532f36d8b
02c164c2dc5c5163bb36531f466b47a5969d50bdec861aecc156ea14abbbf6c24b
0385868f81aa668ef3dd6769b8ac55aeaccc344972397629e77632aaa13bb16473
02a0338ec5d9998048690cdebbc9f7a65f2ca6546c54be3c121355c834d39d99d6
02d392869096193c8dcbcca9f169e447eb51017cd59261f40207a60230ab1c8618
.
.
032e4311413bc458a9920d81c106980b877cd6eab1d533e34fe7513edd5734b710
```

2. -f Address input data is as follows. The data downloaded from the website is directly used as input.

```
3gs5efa8jftqghp9cgjoounkdqegzxbmik 4499984877
3du14mcg7mravllqyosquknl5y2r2rskjf 4499959472
15qdb9ocfg7epcgkdsc3lf2ztktfnfmb4h 4499959107
1kzlwxcdx82ysecm2rwzvnssgclaifbt7r 4499934503
1ksuwcoubisb8fsxjjht75ymsfgnswrndo 4499761694
17unwje5jylxvngcwtlhvbshe2ewasfhbr 4499743048
.
.
bc1qe6jzdxwgw2yxxu7rgj4dfq3ah5vgu8zgdvc6ql 1
```
3. -o hits the match. The public key and address with balance, including the balance, are as follows:


```
0290a2f9989d3ee835d80f6acff19fc5c2adc01caa693d4f54b84c1508c1b0d86f 3gs5efa8jftqghp9cgjoounkdqegzxbmik 4499984877
027a4534be73c419f15c78ec292fcd393ce9315489a57a26da9b55e4d532f36d8b 3du14mcg7mravllqyosquknl5y2r2rskjf 4499959472
02c164c2dc5c5163bb36531f466b47a5969d50bdec861aecc156ea14abbbf6c24b 15qdb9ocfg7epcgkdsc3lf2ztktfnfmb4h 4499959107
0385868f81aa668ef3dd6769b8ac55aeaccc344972397629e77632aaa13bb16473 1kzlwxcdx82ysecm2rwzvnssgclaifbt7r 4499934503
02a0338ec5d9998048690cdebbc9f7a65f2ca6546c54be3c121355c834d39d99d6 1ksuwcoubisb8fsxjjht75ymsfgnswrndo 4499761694
02d392869096193c8dcbcca9f169e447eb51017cd59261f40207a60230ab1c8618 17unwje5jylxvngcwtlhvbshe2ewasfhbr 4499743048
.
.
032e4311413bc458a9920d81c106980b877cd6eab1d533e34fe7513edd5734b710 bc1qe6jzdxwgw2yxxu7rgj4dfq3ah5vgu8zgdvc6ql 1
```

4. Add -x, -o, and the output matches successfully. The public key is as follows:
```
0290a2f9989d3ee835d80f6acff19fc5c2adc01caa693d4f54b84c1508c1b0d86f
027a4534be73c419f15c78ec292fcd393ce9315489a57a26da9b55e4d532f36d8b
02c164c2dc5c5163bb36531f466b47a5969d50bdec861aecc156ea14abbbf6c24b
0385868f81aa668ef3dd6769b8ac55aeaccc344972397629e77632aaa13bb16473
02a0338ec5d9998048690cdebbc9f7a65f2ca6546c54be3c121355c834d39d99d6
02d392869096193c8dcbcca9f169e447eb51017cd59261f40207a60230ab1c8618
.
.
032e4311413bc458a9920d81c106980b877cd6eab1d533e34fe7513edd5734b710
```



CashAddr Without Prefix: For Bitcoin Cash (BCH) CashAddr, the program generates and checks the address string without the prefix (like bitcoincash:). Please ensure your target address file for BCH also does not contain these prefixes.

# If you need the public key of the blockchain, please go to my other library to extract the public key program. They are together and not free. You need to pay $50 to get the compressed password. It can also be used for paid programs released later, which is equivalent to paying a one-time membership fee, except for non-special programs.
```
https://github.com/8891689/Blockchain-Public-Key-Extractor
```
An address with a balance is required, please download it from the website below.

# Get the world's richest addresses ranking for free
```
http://addresses.loyce.club/

https://blockchair.com/dumps
```
# The public key mentioned alone verifies whether there is a balance.
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

1. ethereum.txt Search in Documentation 100000000000000

grep -B 1 "100000000000000" ethereum.txt

2. The Merge and Remove Duplicates command merges the two files 1.txt and 2.txt into one file 1.2.txt after removing duplicates.

cat 1.txt 2.txt | sort -u > 1.2.txt 

3. Remove duplicate commands to remove redundant data in the 1.txt document, such as addresses or public keys, and make it a unique 1.2.txt

sort -u 1.txt > 1.2.txt

4. Count the number of lines in the command 1.2.txt document.

wc -l 1.2.txt


5. Various addresses and hash values, as well as public key extraction commands, such as extracting only the address of the required length from the document, as well as the hash value 160, the public key, the document name in front, and the output name behind.

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


grep -o -E '\b(0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128})\b' 1111111111111111111111111111111111.txt > 公鑰.00000000.txt     // Extract the compressed and uncompressed public keys from the garbled data.

grep -o -E '\b([13][1-9A-HJ-NP-Za-km-z]{30,34}|bc1[0-9a-z]{39,59})\b' btc.txt > btc.txt_addresses.txt    // Extract BTC addresses starting with 1, 3, bc1 from the chaotic data, where the bc1 address contains script addresses with multiple signatures.

grep -o -E '\b([13][1-9A-HJ-NP-Za-km-z]{30,34}|bc1[0-9a-z]{39,44})\b' btc.txt > btc_addresses.txt    // Extract BTC addresses starting with 1, 3, bc1 from the chaotic data, where the bc1 address does not contain the script address of multiple signatures.

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
