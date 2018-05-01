#define STATE_MATRIX_SIZE 4
#define NUM_CHARS_BLKSZ_128 16
#define TERMINAL_CHAR '\r'

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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

void pretty_print_int_matrix(unsigned int state[][STATE_MATRIX_SIZE]) {
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

void pretty_print_hex_matrix(unsigned int state[][STATE_MATRIX_SIZE]) {
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

unsigned int char_to_hex(char ch) {
    if(isdigit(ch)) {
        return ch - '0';
    } else if(isupper(ch)) {
        return ch - 'A';
    } else if(islower(ch)) {
        return ch - 'a';
    } else if(iscntrl(ch)) {
        return ch - '\0';
    } else {
        // TODO: fix for non control, digit, upper and lower case letters
        return ch;
    }
}
/**
 * Fills the state matrix from the ASCII string provided. Note that this function
 * should only be used for 128 bit blocks (so only strings with 16 characters will work)
**/
void ascii_to_hex_128(const char* str, unsigned int state[][STATE_MATRIX_SIZE]) {
    int i;
    int row = -1;
    int col = 0;
    int len = strlen(str);

    for(i = 0; i < len; i++) {
        ++row;
        state[row][col] = char_to_hex(str[i]);
        if(row == STATE_MATRIX_SIZE - 1) {
            row = -1;
            ++col;
        }
    }
}

int main(int argc, char const *argv[]) {
    // key size is 128 bits which is 16 characters
    // Additional is for the null character
    char key[17] = "";
    // max plaintext size is 100 (otherwise read from file)
    char plain_text[100] = "";
    // file to encrypt
    char* file_name = "";

    unsigned int key_state[4][4];
    unsigned int cipher_state[4][4];

    parse_command_line_args(argc, argv, key, plain_text);
    printf("\nEncryption key is %s and the plaintext is %s\n", key, plain_text);

    pad_string_128(key);
    ascii_to_hex_128(key, key_state);
    pretty_print_hex_matrix(key_state);
    // ascii_to_hex(plain_text, cipher_state);

    return 0;
}
