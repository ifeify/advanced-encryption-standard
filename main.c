#define STATE_MATRIX_SIZE 4
#define NUM_CHARS_BLKSZ_128 16
#define MAX_CHARS_PLAINTEXT 120
#define MAX_CHARS_CIPHERTEXT 128
#define AES_128_ROUNDS 10
#define TERMINAL_CHAR '\0'
#define ERROR_COMMAND_LINE_ARGS -2
#define TEST_BIT(number, bit_position)((number) & (1 << bit_position))

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

/**
 * @param temp_key is an array of size 4
 *
**/
void get_round_temp_key(unsigned char* temp_key, int round_number) {
    left_rotate_once(temp_key, STATE_MATRIX_SIZE);
    int i;
    for(i = 0; i < STATE_MATRIX_SIZE; i++) {
        char val = temp_key[i];
        int bottom_half = val & 0x0f;
        int top_half = (val & 0xf0) >> 4;
        temp_key[i] = AES_SBOX[top_half * NUM_CHARS_BLKSZ_128 + bottom_half];
    }

    temp_key[0] = temp_key[0] ^ ROUND_CONSTANT[round_number];
}

void next_round_key(unsigned char (*round_key)[STATE_MATRIX_SIZE],
                                                    int round_number) {
    unsigned char temp_round_key[4] = {0};

    // the last column in the state key will be used to generate the temp round key
    temp_round_key[0] = *(*(round_key + 0) + 3);
    temp_round_key[1] = *(*(round_key + 1) + 3);
    temp_round_key[2] = *(*(round_key + 2) + 3);
    temp_round_key[3] = *(*(round_key + 3) + 3);

    get_round_temp_key(temp_round_key, round_number);

    // generate first column from temp round key and part of the key (i.e. word)
    // from the previous round
    *(*(round_key)) = *(*(round_key)) ^ temp_round_key[0];
    *(*(round_key + 1)) = *(*(round_key + 1)) ^ temp_round_key[1];
    *(*(round_key + 2)) = *(*(round_key + 2)) ^ temp_round_key[2];
    *(*(round_key + 3)) = *(*(round_key + 3)) ^ temp_round_key[3];

    // generate 2nd column from previous column and part of the key (i.e word)
    // from the previous round
    *(*(round_key) + 1) = *(*(round_key) + 1) ^ *(*(round_key));
    *(*(round_key + 1) + 1) = *(*(round_key + 1) + 1) ^ *(*(round_key + 1));
    *(*(round_key + 2) + 1) = *(*(round_key + 2) + 1) ^ *(*(round_key + 2));
    *(*(round_key + 3) + 1) = *(*(round_key + 3) + 1) ^ *(*(round_key + 3));

    // generate 3rd column from previous column and part of the key (i.e word)
    // from the previous round
    *(*(round_key) + 2) = *(*(round_key) + 2) ^ *(*(round_key) + 1);
    *(*(round_key + 1) + 2) = *(*(round_key + 1) + 2) ^ *(*(round_key + 1) + 1);
    *(*(round_key + 2) + 2) = *(*(round_key + 2) + 2) ^ *(*(round_key + 2) + 1);
    *(*(round_key + 3) + 2) = *(*(round_key + 3) + 2) ^ *(*(round_key + 3) + 1);

    // generate 4th column from previous column and part of the key (i.e word)
    // from the previous round
    *(*(round_key) + 3) = *(*(round_key) + 3) ^ *(*(round_key) + 2);
    *(*(round_key + 1) + 3) = *(*(round_key + 1) + 3) ^ *(*(round_key + 1) + 2);
    *(*(round_key + 2) + 3) = *(*(round_key + 2) + 3) ^ *(*(round_key + 2) + 2);
    *(*(round_key + 3) + 3) = *(*(round_key + 3) + 3) ^ *(*(round_key + 3) + 2);
}

void add_round_key(unsigned char cipher_state[][STATE_MATRIX_SIZE], unsigned char round_key[][STATE_MATRIX_SIZE]) {
    int row, col;
    for(row = 0; row < STATE_MATRIX_SIZE; row++) {
        for(col = 0; col < STATE_MATRIX_SIZE; col++) {
            cipher_state[row][col] = cipher_state[row][col] ^ round_key[row][col];
        }
    }
}

char gf_multiply_one(unsigned char num) {
    return num;
}

char gf_multiply_two(const unsigned char num) {
    unsigned char val = num << 1;
    // check if high end bit in a byte is 1
    // 0x80 is 1000 0000 and is the same as bit shifting
    // the number 1 seven times to the left
    if((num & 0x80)) {
        return val ^ 0x1B;
    }
    return val;
}

char gf_multiply_three(unsigned char num) {
    // 3 = 2 ^ 1
    return gf_multiply_two(num) ^ gf_multiply_one(num);
}

/**
 * @param gf_constant - will either be 1, 2 or 3
**/
char gf_multiply(const unsigned char gf_constant, const unsigned char num) {
    if(gf_constant == 0x01) {
        return gf_multiply_one(num);
    } else if(gf_constant == 0x02) {
        return gf_multiply_two(num);
    } else {
        return gf_multiply_three(num);
    }
}

/**
 * @param row_ptr - is a pointer to the starting address of the row
                    the cell to mix resides in (in a 2D array)
 * @param row - is row number number of the cell to mix
 * @param column - is the column number of the cell to mix
**/
char mix_column_cell(unsigned char state[][STATE_MATRIX_SIZE], int row, int column) {
    return gf_multiply(GF_MATRIX[row][0], state[0][column])
            ^ gf_multiply(GF_MATRIX[row][1], state[1][column])
            ^ gf_multiply(GF_MATRIX[row][2], state[2][column])
            ^ gf_multiply(GF_MATRIX[row][3], state[3][column]);
}

void mix_columns(unsigned char cipher_state[][STATE_MATRIX_SIZE]) {
    int col;
    char temp[STATE_MATRIX_SIZE] = {0, 0, 0, 0};

    for(col = 0; col < STATE_MATRIX_SIZE; col++) {
        temp[0] = mix_column_cell(cipher_state, 0, col);
        temp[1] = mix_column_cell(cipher_state, 1, col);
        temp[2] = mix_column_cell(cipher_state, 2, col);
        temp[3] = mix_column_cell(cipher_state, 3, col);

        // update current column before moving on
        cipher_state[0][col] = temp[0];
        cipher_state[1][col] = temp[1];
        cipher_state[2][col] = temp[2];
        cipher_state[3][col] = temp[3];
    }
}

void aes_encrypt_block(unsigned char key_state[][STATE_MATRIX_SIZE], unsigned char cipher_state[][STATE_MATRIX_SIZE]) {
    printf("\nRound 0 Key:\n");
    pretty_print_hex_matrix(key_state);

    printf("\nInitial plaintext:\n");
    pretty_print_hex_matrix(cipher_state);

    add_round_key(cipher_state, key_state);
    printf("\nAfter first AddRoundKey:\n");
    pretty_print_hex_matrix(cipher_state);

    int round_number;
    for(round_number = 1; round_number <= AES_128_ROUNDS; round_number++) {
        next_round_key(key_state, round_number);
        printf("\n****************************************************\n");
        printf("Round %d Key is:\n", round_number);
        pretty_print_hex_matrix(key_state);

        if(round_number == AES_128_ROUNDS) { // MixColumns operation missing from last round
            sub_bytes_transform(cipher_state);
            printf("\nAfter subBytes transformation:\n");
            pretty_print_hex_matrix(cipher_state);

            shift_rows(cipher_state);
            printf("\nAfter ShiftRows operation:\n");
            pretty_print_hex_matrix(cipher_state);

            add_round_key(cipher_state, key_state);
            printf("\nAfter AddRoundKey operation:\n");
            pretty_print_hex_matrix(cipher_state);
        } else {
            sub_bytes_transform(cipher_state);
            printf("\nAfter subBytes transformation:\n");
            pretty_print_hex_matrix(cipher_state);

            shift_rows(cipher_state);
            printf("\nAfter ShiftRows operation:\n");
            pretty_print_hex_matrix(cipher_state);

            mix_columns(cipher_state);
            printf("\nAfter MixColumns operation:\n");
            pretty_print_hex_matrix(cipher_state);

            add_round_key(cipher_state, key_state);
            printf("\nAfter AddRoundKey operation:\n");
            pretty_print_hex_matrix(cipher_state);
        }

        printf("\n********************* End Round %d ***********************\n", round_number);
    }
}

int main(int argc, char const *argv[]) {
    // key size is 128 bits which is 16 characters
    // Additional is for the null character
    char key[17] = "";
    // max plaintext size is 100 (otherwise read from file)
    char plain_text[MAX_CHARS_PLAINTEXT] = "";
    char cipher_text[MAX_CHARS_CIPHERTEXT] = "";
    // file to encrypt
    char* file_name = "";

    unsigned char initial_key_state[4][4];
    unsigned char round_key[4][4];
    unsigned char cipher_state[4][4];

    parse_command_line_args(argc, argv, key, plain_text);
    if(strlen(plain_text) > MAX_CHARS_PLAINTEXT || strlen(key) > NUM_CHARS_BLKSZ_128) {
        printf("Plaintext cannot be more than %d characters long.\n", MAX_CHARS_PLAINTEXT);
        printf("Encryption key cannot be more than %d characters", NUM_CHARS_BLKSZ_128);
        exit(ERROR_COMMAND_LINE_ARGS);
    }

    printf("\nEncryption key is %s and the plaintext is %s\n", key, plain_text);

    pad_string_128(key);
    ascii_to_hex_128(key, 0, strlen(key), initial_key_state);

    int pos = 0;
    int block_number = 1;
    // Take the plaintext 16 characters at a time since each AES block is 128 bits long
    while(pos < strlen(plain_text)) {
        printf("\nPlaintext block is: %.*s\n", NUM_CHARS_BLKSZ_128, plain_text + pos);
        ascii_to_hex_128(plain_text, pos, NUM_CHARS_BLKSZ_128, cipher_state);

        printf("\nInitial plaintext state for block %d is:\n", block_number);
        pretty_print_hex_matrix(cipher_state);

        aes_encrypt_block(initial_key_state, cipher_state);

        printf("\nFinal ciphertext for block %d is:\n", block_number);
        pretty_print_hex_matrix(cipher_state);

        block_number++;
        pos += NUM_CHARS_BLKSZ_128;
        memset(cipher_state, 0, sizeof(cipher_state));
    }
    return 0;
}
