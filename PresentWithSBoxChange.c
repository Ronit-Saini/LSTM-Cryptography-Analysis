#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct __attribute__((__packed__)) byte{
    uint8_t nibble1 : 4;
    uint8_t nibble2 : 4;
} byte;

//Made the first and second bit output same
uint8_t S[] = {0xC, 0xC, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};

uint8_t invS[] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

uint8_t P[] = {0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63};

byte* fromHexStringToBytes (char *block){
    byte* bytes = malloc(8 * sizeof(byte));
    int i;

    for (i=0; i<8; i++){
        bytes[i].nibble1 = (block[2*i]>='0' && block[2*i]<='9')? (block[2*i] - '0') : (block[2*i] - 'a' + 10);
        bytes[i].nibble2 = (block[2*i+1]>='0' && block[2*i+1]<='9')? (block[2*i+1] - '0') : (block[2*i+1] - 'a' + 10);
    }
    return bytes;
}

uint64_t fromBytesToLong (byte* bytes){
    uint64_t result = 0;
    int i;

    for (i=0; i<8; i++){
        result = (result << 4) | (bytes[i].nibble1 & 0xFUL);
        result = (result << 4) | (bytes[i].nibble2 & 0xFUL);
    }
    return result;
}

uint64_t fromHexStringToLong (char* block){
    uint64_t result;
    int i;

    for (i=0; i<16; i++)
        result = (result << 4) | ((block[i]>='0' && block[i]<='9')? (block[i] - '0') : (block[i] - 'A' + 10));
    return result;
}

byte* fromLongToBytes (uint64_t block){
    byte* bytes = malloc (8 * sizeof(byte));
    int i;

    for (i=7; i>=0; i--){
        bytes[i].nibble2 = (block >> 2 * (7 - i) * 4) & 0xFLL;
        bytes[i].nibble1 = (block >> (2 * (7 - i) + 1) * 4) & 0xFLL;
    }
    return bytes;
}

char* fromLongToHexString (uint64_t block){
    char* hexString = malloc (17 * sizeof(char));
    sprintf(hexString, "%016llx", block);
    return hexString;
}

uint8_t Sbox(uint8_t input){
    return S[input];
}

uint8_t inverseSbox(uint8_t input){
    return invS[input];
}

uint64_t permute(uint64_t source){
    uint64_t permutation = 0;
    int i;
    for (i=0; i<64; i++){
        int distance = 63 - i;
        permutation = permutation | ((source >> distance & 0x1) << 63 - P[i]);
    }
    return permutation;
}

uint64_t inversepermute(uint64_t source){
    uint64_t permutation = 0;
    int i;
    for (i=0; i<64; i++){
        int distance = 63 - P[i];
        permutation = (permutation << 1) | ((source >> distance) & 0x1);
    }
    return permutation;
}

uint16_t getKeyLow(char* key){
    int i;
    uint16_t keyLow = 0;
    for (i=16; i<20; i++)
        keyLow = (keyLow << 4) | (((key[i]>='0' && key[i]<='9')? (key[i] - '0') : (key[i] - 'A' + 10)) & 0xF);
    return keyLow;
}
uint64_t* generateSubkeys(char* key){
    uint64_t keyHigh = fromHexStringToLong(key);
    uint16_t keyLow = getKeyLow(key);
    uint64_t* subKeys = malloc(32 * (sizeof(uint64_t)));
    int i;
    subKeys[0] = keyHigh;
    for (i=1; i<32; i++){
        uint64_t temp1 = keyHigh, temp2 = keyLow;
        keyHigh = (keyHigh << 61) | (temp2 << 45) | (temp1 >> 19);
        keyLow = ((temp1 >> 3) & 0xFFFF);
        uint8_t temp = Sbox(keyHigh >> 60);
        keyHigh = keyHigh & 0x0FFFFFFFFFFFFFFFLL;
        keyHigh = keyHigh | (((uint64_t)temp) << 60);
        keyLow = keyLow ^ ((i & 0x01) << 15); 
        keyHigh = keyHigh ^ (i >> 1); 
        subKeys[i] = keyHigh;
    }
    return subKeys;
}
char* encrypt(char* plaintext, char* key){
    uint64_t* subkeys = generateSubkeys(key);
    uint64_t state = fromHexStringToLong(plaintext);
    int i, j;
    for (i=0; i<31; i++){
        state = state ^ subkeys[i];
        byte* stateBytes = fromLongToBytes(state);
        for (j=0; j<8; j++){
            stateBytes[j].nibble1 = Sbox(stateBytes[j].nibble1);
            stateBytes[j].nibble2 = Sbox(stateBytes[j].nibble2);
        }
        state = permute(fromBytesToLong(stateBytes));
        free(stateBytes);
    }
    state = state ^ subkeys[31];
    free(subkeys);
    return fromLongToHexString(state);
}
char* decrypt(char* ciphertext, char* key){
    uint64_t* subkeys = generateSubkeys(key);
    uint64_t state = fromHexStringToLong(ciphertext);
    int i, j;
    for (i=0; i<31; i++){
        state = state ^ subkeys[31 - i];
        state = inversepermute(state);
        byte* stateBytes = fromLongToBytes(state);
        for (j=0; j<8; j++){
            stateBytes[j].nibble1 = inverseSbox(stateBytes[j].nibble1);
            stateBytes[j].nibble2 = inverseSbox(stateBytes[j].nibble2);
        }
        state = fromBytesToLong(stateBytes);
        free(stateBytes);
    }
    state = state ^ subkeys[0];
    free(subkeys);
    return fromLongToHexString(state);
}
int main(int argc, char *argv[]){
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key> <plain_text>\n", argv[0]);
        return 1;
    }
    char *key = argv[1];      
    char *plain_text = argv[2];
    char *cipher_text;
    cipher_text = encrypt(plain_text, key);
    puts(cipher_text);

    return 0;
}