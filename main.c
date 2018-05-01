#include <stdio.h>
#include <unistd.h>

void parse_command_line_args(int argc, char const* argv[], char* key, char* plaintext) {
    int opt = 0;

    while((opt = getopt(argc, argv, "k:p:")) != -1) {
        switch(opt) {
            case 'k':
                key = optarg;
                break;
            case 'p':
                plaintext = optarg;
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

int main(int argc, char const *argv[]) {
    char* key = NULL;
    char* plain_text = NULL;
    parse_command_line_args(argc, argv, key, plain_text);
    return 0;
}
