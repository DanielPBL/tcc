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

const char* pcszPassphrase = "open sezamee";

static void gen_callback(int iWhat, int inPrime, void* pParam);
static void init_openssl(void);
static void cleanup_openssl(void);
static int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass);
static EVP_PKEY* create_rsa_key(RSA *pRSA);
static void handle_openssl_error(void);

int main(int argc, char **argv)
{
    int iRet = EXIT_SUCCESS;
    EVP_PKEY* pPrivKey = NULL;
    EVP_PKEY* pPubKey  = NULL;
    FILE*     pFile    = NULL;
    const EVP_CIPHER* pCipher = NULL;
    init_openssl();

    RSA *pRSA      = NULL;
    pRSA = RSA_generate_key(2048,RSA_3,gen_callback,NULL);    
    pPrivKey = create_rsa_key(pRSA);
    pPubKey  = create_rsa_key(pRSA);

    if(pPrivKey && pPubKey)
    {/* Save the keys */
        if((pFile = fopen("privkey.pem","wt")) && (pCipher = EVP_aes_256_cbc()))
        {

            if(!PEM_write_PrivateKey(pFile,pPrivKey,pCipher,
                                    (unsigned char*)pcszPassphrase,
                                    (int)strlen(pcszPassphrase),NULL,NULL))
            {
                fprintf(stderr,"PEM_write_PrivateKey failed.\n");
                handle_openssl_error();
                iRet = EXIT_FAILURE;
            }
            fclose(pFile);
            pFile = NULL;
            if(iRet == EXIT_SUCCESS)
            {
                if((pFile = fopen("pubkey.pem","wt")) && PEM_write_PUBKEY(pFile,pPubKey))
                    fprintf(stderr,"Both keys saved.\n");
                else
                {
                    handle_openssl_error();
                    iRet = EXIT_FAILURE;
                }
                if(pFile)
                {
                    fclose(pFile);
                    pFile = NULL;
                }
            }
        }
        else
        {
            fprintf(stderr,"Cannot create \"privkey.pem\".\n");
            handle_openssl_error();
            iRet = EXIT_FAILURE;
            if(pFile)
            {
                fclose(pFile);
                pFile = NULL;
            }
        }
        if(iRet == EXIT_SUCCESS)
        {/* Read the keys */
            //EVP_PKEY_free(pPrivKey);
            pPrivKey = NULL;
            //EVP_PKEY_free(pPubKey);
            pPubKey = NULL;

            if((pFile = fopen("privkey.pem","rt")) && 
               (pPrivKey = PEM_read_PrivateKey(pFile,NULL,passwd_callback,(void*)pcszPassphrase)))
            {
                fprintf(stderr,"Private key read.\n");
            }
            else
            {
                fprintf(stderr,"Cannot read \"privkey.pem\".\n");
                handle_openssl_error();
                iRet = EXIT_FAILURE;
            }
            if(pFile)
            {
                fclose(pFile);
                pFile = NULL;
            }

            if((pFile = fopen("pubkey.pem","rt")) && 
               (pPubKey = PEM_read_PUBKEY(pFile,NULL,NULL,NULL)))
            {
                fprintf(stderr,"Public key read.\n");
            }
            else
            {
                fprintf(stderr,"Cannot read \"pubkey.pem\".\n");
                handle_openssl_error();
                iRet = EXIT_FAILURE;
            }
        }
    }

    if(pPrivKey)
    {
        EVP_PKEY_free(pPrivKey);
        pPrivKey = NULL;
    }
    if(pPubKey)
    {
        EVP_PKEY_free(pPubKey);
        pPubKey = NULL;
    }
    cleanup_openssl();
    return iRet;
}

EVP_PKEY* create_rsa_key(RSA *pRSA)
{
    EVP_PKEY* pKey = NULL;
    pKey = EVP_PKEY_new();
    if(pRSA && pKey && EVP_PKEY_assign_RSA(pKey,pRSA))
    {
        /* pKey owns pRSA from now */
        if(RSA_check_key(pRSA) <= 0)
        {
            fprintf(stderr,"RSA_check_key failed.\n");
            handle_openssl_error();
            EVP_PKEY_free(pKey);
            pKey = NULL;
        }
    }
    else
    {
        handle_openssl_error();
        if(pRSA)
        {
            RSA_free(pRSA);
            pRSA = NULL;
        }
        if(pKey)
        {
            EVP_PKEY_free(pKey);
            pKey = NULL;
        }
    }
    return pKey;
}

void gen_callback(int iWhat, int inPrime, void* pParam)
{
    char c='*';
    switch(iWhat)
    {
        case 0: c = '.';  break;
        case 1: c = '+';  break;
        case 2: c = '*';  break;
        case 3: c = '\n'; break;
    }
    fprintf(stderr,"%c",c);
}

int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}

void init_openssl(void)
{
    if(SSL_library_init())
    {
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
    }
    else
        exit(EXIT_FAILURE);
}

void cleanup_openssl(void)
{
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(0);
    EVP_cleanup();
}

void handle_openssl_error(void)
{
    ERR_print_errors_fp(stderr);
}