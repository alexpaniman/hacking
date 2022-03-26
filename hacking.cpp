#include <cctype>
#include <cstdint>
#include <iostream>
#include <string.h>
#include <strings.h>

__asm__("jmp .continue_execution_global;                                                  \n"
        "        .string \"See this? I'm confident, you do. \";                           \n"
        "        .string \"Can you guess what this is? Yeah, you're right.  \";           \n"
        "        .string \"Inline string literals! Poor code alignment :(\";              \n"
        "        .string \"Sorry for stealing idea btw.\";                                \n"
        "        .string \"But I inveneted it before you told me, so it doesn't count!\"; \n"
        "    .continue_execution_global:   ");

#include "crypto.h"

// ------------------------------ CAESAR CIPHER ------------------------------
struct caesar_encrypted_string {
    const char* string;
    int alphabet_shift;
};

char caesar_cipher_encrypt_symbol(char symbol, int key) {
    char lowercased_symbol = tolower(symbol);
    if (lowercased_symbol < 'a' || lowercased_symbol > 'z')
        return symbol;

    size_t alphabet_length = 'z' - 'a' + 1;
    char decrypted_symbol =
        'a' + (alphabet_length + lowercased_symbol - 'a' + key) % alphabet_length;

    return isupper(symbol) ? toupper(decrypted_symbol) : decrypted_symbol;
}

void caesar_encrypt(char* string, int key) {
    for (; *string != '\0'; ++ string)
        *string = caesar_cipher_encrypt_symbol(*string, key);
}

// ------------------------------ GRANT ACCESS -------------------------------

const caesar_encrypted_string grant_access_string = { "Hjjlzz nyhualk!", 7 };

extern "C" void asm_printf(const char* format, ...);

void grant_access(void) {
    char access_granted_string[64] = {};
    strcpy(access_granted_string, grant_access_string.string);

    caesar_encrypt(access_granted_string, - grant_access_string.alphabet_shift);
    asm_printf("%s\n", access_granted_string);

}

// ------------------------------ CASE MAPPING -------------------------------
bool check_case(char* string, int* case_map) {
    for (; *case_map != /* End marker */ -1 && *string != '\0'; ++ case_map, ++ string)
        if (isalpha(*string) && (!isupper(*string)) == *case_map)
            return false;

    return true;
}

// ---------------------------------- DATA -----------------------------------
static const int password_case_map[] = { 1, 0,
                                         1, 0,
                                         1, 0, 0,
                                         1, 0, 0, 0,
                                         1, 0, 0, 0, 0, 0,
                                         1, 0, 0, 0, 0, 0, 0, 0, 0,
                                         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         /* End marker */ -1 };

bool test_password(char* password_to_test, caesar_encrypted_string* encrypted) {
    __asm__("jmp .continue_execution;                                                \n"
            "        .string \"Hi, Danny! Here is cleartext password for you: \";    \n"
            "        .string \"'qwerty'. JK it will not be as easy, keep reading!\"; \n"
            "    .continue_execution:   ");

    char password_buffer[32] = {};
    strcpy(password_buffer, password_to_test);

    if (!check_case(password_buffer, (int*) password_case_map))
        return false;

    caesar_encrypt(password_buffer, encrypted->alphabet_shift);
    if (strcasecmp(password_buffer, encrypted->string) == 0)
        return true;

    return false;
}

// ---------------------------- PASSWORD_PIECES ------------------------------
struct obfuscated_piece_of_string {
    const char* obfuscated_pointer;
    const size_t size;
};

const size_t ADDRESS_OBFUSCATOR_MULTIPLIER = 2;

obfuscated_piece_of_string create_obfuscated_string_piece(const char* piece) {
    return { (char*) ((uintptr_t) piece * ADDRESS_OBFUSCATOR_MULTIPLIER), strlen(piece) };
}

const char* get_string_from_obfuscated_piece(obfuscated_piece_of_string piece) {
    return (char*) ((uintptr_t) piece.obfuscated_pointer / ADDRESS_OBFUSCATOR_MULTIPLIER);
}

__asm__("jmp .continue_execution_before_password_pieces;                                  \n"
        "        .string \"I will give you free advise, pay attention to stuff below: \"; \n"
        "    .continue_execution_before_password_pieces:   ");

obfuscated_piece_of_string password[] = {
    create_obfuscated_string_piece("MK"),
    create_obfuscated_string_piece("OCK"),
    create_obfuscated_string_piece("B M"),
    create_obfuscated_string_piece("S"),
    create_obfuscated_string_piece("ZROB")
};

const size_t password_caesar_key = 10; 

char* build_string_from_pieces(obfuscated_piece_of_string* pieces, size_t pieces_count) {
    size_t length = 0;
    for (int i = 0; i < pieces_count; ++ i)
        length += pieces[i].size;

    char* joined_string = (char*) calloc(sizeof *joined_string,
                                         length + 1 /* for '\0' */);

    for (int i = 0; i < pieces_count; ++ i) {
        const char* current_piece =
            get_string_from_obfuscated_piece(pieces[i]);

        strcpy(joined_string, current_piece);
        joined_string += pieces[i].size;
    }

    return joined_string - length;
}

// ------------------ ALTERNATIVE SHA256 ENCODED PASSWORD --------------------

__asm__("jmp .continue_execution_before_password_hash;                                               \n"
        "        .string \"One more thing! Looks like there's SHA256 hashed password somwhere!...\"; \n"
        "        .string \"Hope it helps!...\";                                                      \n"
        "    .continue_execution_before_password_hash:   ");

const char* sha256_hashed_password = "e020bdf568793dee747a220086c5e53c8b3af5abd959383a31297f303577efe6";

const size_t BITS_IN_BYTE = 8;
bool compare_with_sha256(const char* entered_password, const char* reference_hash) {
    uint32_t result_sha256_hash[HASH_SIZE];
    hash_with_sha_256(entered_password, strlen(entered_password), result_sha256_hash);

    for (int i = 0; i < HASH_SIZE; ++ i) {
        char one_number_buffer[BITS_IN_BYTE + 1] = {};
        strncpy(one_number_buffer, reference_hash + i * HASH_SIZE, HASH_SIZE);

        uint32_t one_piece = strtoll(one_number_buffer, NULL, 16);
        if (one_piece != result_sha256_hash[i])
            return false;
    }

    return true;
}

#define array_size(array) sizeof(array) / sizeof(*array)

int main(void) {
    printf("Enter password: ");

    char* entered_password = NULL;
    scanf("%m[^\n]", &entered_password);

    if (compare_with_sha256(entered_password, sha256_hashed_password))
        grant_access();
    else {
        char* password_string = build_string_from_pieces(password, array_size(password));
        caesar_encrypted_string encoded_password = {
            password_string, password_caesar_key
        };

        if (test_password(entered_password, &encoded_password)) 
            grant_access();

        free(password_string);
    }

    free(entered_password);
}
