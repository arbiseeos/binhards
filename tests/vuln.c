#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[100];
    
    if (argc > 1) {
        strcpy(buffer, argv[1]);
        printf("Input: %s\n", buffer);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }

    char input[100];
    printf("Enter something (using gets - unsafe!): ");
    gets(input);
    printf("You entered: %s\n", input);

    return 0;
}