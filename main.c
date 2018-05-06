#define STATE_MATRIX_SIZE 4
#define NUM_CHARS_BLKSZ_128 16
#define AES_128_ROUNDS 16
#define TERMINAL_CHAR '\r'
#define ERROR_COMMAND_LINE_ARGS -2

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "util.h"

void parse_command_line_args(int argc, char const* argv[], char* key, char* plain_text) {
    int opt = 0;

    while((opt = getopt(argc, argv, "k:p:")) != -1) {
        switch(opt) {
            case 'k':
                strcpy(key, optarg);
                break;
            case 'p':
                strcpy(plain_text, optarg);
                break;
            case '?': // when user provide the required parameters
                if(optopt == 'k') {
                    printf("\nEncryption key not specified");
                } else if(optopt == 'p') {
                    printf("\nPlaintext not specified");
                } else {
                    printf("\nInvalid option");
                }
                break;
        }
    }
}

void pad_string_128(char* str) {
    int i = 0;
    int len = strlen(str);
    if(len < NUM_CHARS_BLKSZ_128) {
        for(i = len; i < NUM_CHARS_BLKSZ_128; i++) {
            str[i] = TERMINAL_CHAR;
        }
    }
}

void pretty_print_int_matrix(unsigned char state[][STATE_MATRIX_SIZE]) {
    int row, col = 0;
    for(row = 0; row < STATE_MATRIX_SIZE; row++) {
        printf("{");
        for(col = 0; col < STATE_MATRIX_SIZE; col++) {
            printf(" %d ", state[row][col]);
        }
        printf("}\n");
    }
    printf("\n");
}

void pretty_print_hex_matrix(unsigned char state[][STATE_MATRIX_SIZE]) {
    int row, col = 0;
    for(row = 0; row < STATE_MATRIX_SIZE; row++) {
        printf("{");
        for(col = 0; col < STATE_MATRIX_SIZE; col++) {
            printf(" %X ", state[row][col]);
        }
        printf("}\n");
    }
    printf("\n");
}

/**
 * Fills the state matrix from the ASCII string provided. Note that this function
 * should only be used for 128 bit blocks (so only strings with 16 characters will work)
 @param len - is the length of the input string
**/
void ascii_to_hex_128(const char* str, int offset, int len, unsigned char state[][STATE_MATRIX_SIZE]) {
    int i;
    int row = -1;
    int col = 0;

    for(i = offset; i < (offset + len); i++) {
        ++row;
        state[row][col] = (int)str[i];
        if(row == STATE_MATRIX_SIZE - 1) {
            row = -1;
            ++col;
        }
    }
}

void sub_bytes_transform(unsigned char cipher_state[][STATE_MATRIX_SIZE]) {
    int row, col = 0;
    for(col = 0; col < STATE_MATRIX_SIZE; col++) {
        for(row = 0; row < STATE_MATRIX_SIZE; row++) {
            char val = cipher_state[row][col];
            int bottom_half = val & 0x0f;
            int top_half = (val & 0xf0) >> 4;
            cipher_state[row][col] = AES_SBOX[top_half * NUM_CHARS_BLKSZ_128 + bottom_half];
        }
    }
}

void left_rotate_once(unsigned char* array, int len) {
    char temp = array[0];
    int i;
    for(i = 0; i < len - 1; i++) {
        array[i] = array[i + 1];
    }
    // i is len - 1 at this point
    array[i] = temp;
}

/**
 * Performs a circular left rotate of the array
**/
void left_rotate(unsigned char* array, int len, int num_rotations) {
    int i;
    for(i = 0; i < num_rotations; i++) {
        left_rotate_once(array, len);
    }
}

void shift_rows(unsigned char cipher_state[][STATE_MATRIX_SIZE]) {
    // rotate left by row number.
    // We're passing the address of the first element in each row
    left_rotate(&cipher_state[1][0], STATE_MATRIX_SIZE, 1);
    left_rotate(&cipher_state[2][0], STATE_MATRIX_SIZE, 2);
    left_rotate(&cipher_state[3][0], STATE_MATRIX_SIZE, 3);
}

void add_round_key(unsigned char cipher_state[][STATE_MATRIX_SIZE], unsigned char round_key[][STATE_MATRIX_SIZE]) {
    int row, col;
    for(row = 0; row < STATE_MATRIX_SIZE; row++) {
        for(col = 0; col < STATE_MATRIX_SIZE; col++) {
            cipher_state[row][col] = cipher_state[row][col] ^ round_key[row][col];
        }
    }
}

void aes_encrypt(unsigned char key_state[][STATE_MATRIX_SIZE], unsigned char cipher_state[][STATE_MATRIX_SIZE]) {
    sub_bytes_transform(cipher_state);
    shift_rows(cipher_state);
}

int main(int argc, char const *argv[]) {
    // key size is 128 bits which is 16 characters
    // Additional is for the null character
    char key[17] = "";
    // max plaintext size is 100 (otherwise read from file)
    char plain_text[100] = "";
    // file to encrypt
    char* file_name = "";

    unsigned char key_state[4][4];
    unsigned char cipher_state[4][4];

    parse_command_line_args(argc, argv, key, plain_text);
    if(strlen(plain_text) > 100 || strlen(key) > NUM_CHARS_BLKSZ_128) {
        printf("Plaintext cannot be more than 100 characters.\n");
        printf("Encryption key cannot be more than %d characters", NUM_CHARS_BLKSZ_128);
        exit(ERROR_COMMAND_LINE_ARGS);
    }

    printf("\nEncryption key is %s and the plaintext is %s\n", key, plain_text);

    pad_string_128(key);
    ascii_to_hex_128(key, 0, strlen(key), key_state);

    int pos = 0;
    // take the plaintext 16 characters at a time since each AES block is 128 bits long
    while(pos < strlen(plain_text)) {
        printf("\nPlaintext block is: %.*s\n", NUM_CHARS_BLKSZ_128, plain_text + pos);
        ascii_to_hex_128(plain_text, pos, NUM_CHARS_BLKSZ_128, cipher_state);

        printf("\nBefore subbytes\n");
        pretty_print_hex_matrix(cipher_state);

        printf("\nAfter subbytes\n");
        sub_bytes_transform(cipher_state);
        pretty_print_hex_matrix(cipher_state);

        printf("\nAfter shift rows\n");
        shift_rows(cipher_state);
        pretty_print_hex_matrix(cipher_state);

        pos += NUM_CHARS_BLKSZ_128;
        memset(cipher_state, 0, sizeof(cipher_state));
    }


    return 0;
}
