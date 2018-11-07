
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>

#include "../shared_headers/ssl_utils.h"

int main(int argc, char const *argv[]) {
    char *s_key, *p_key, *sign;
    char msg[] = "DANIEL LOPES";

    s_key = load_file_to_buff(argv[1]);
    p_key = load_file_to_buff(argv[2]);

    fprintf(stdout, "%s\n", s_key);
    fprintf(stdout, "%s\n", p_key);

    sign = signMessage(s_key, msg);
    fprintf(stdout, "%s\n", sign);


    if (verifySignature(p_key, msg, sign)) {
        printf("OK\n");
    } else {
        printf("NOT OK\n");
    }

    if (s_key)
        free(s_key);
    if (p_key)
        free(p_key);

    return EXIT_SUCCESS;
}
