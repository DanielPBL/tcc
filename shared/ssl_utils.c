#include "../shared_headers/ssl_utils.h"

RSA* createPrivateRSA(const char *key) {
  RSA *rsa = NULL;
  
  BIO * keybio = BIO_new_mem_buf((void*)key, -1);
  if (keybio==NULL) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  if (rsa==NULL) {
    ERR_print_errors_fp(stderr);
  }
  return rsa;
}

bool RSASign( RSA* rsa, 
              const unsigned char* Msg, 
              size_t MsgLen,
              unsigned char** EncMsg, 
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  EVP_MD_CTX_cleanup(m_RSASignCtx);
  return true;
}

unsigned char* signMessage(const char *privateKey, const unsigned char *plainText,
    size_t textLength, size_t *encMessageLength) {
  RSA* privateRSA = createPrivateRSA(privateKey);
  unsigned char* encMessage;

  RSASign(privateRSA, plainText, textLength, &encMessage, encMessageLength);

  return encMessage;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

RSA* createPublicRSA(const char *key) {
  RSA *rsa = NULL;
  BIO *keybio;
  
  keybio = BIO_new_mem_buf((void*)key, -1);
  if (keybio==NULL) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  if (rsa==NULL) {
    ERR_print_errors_fp(stderr);
  }
  return rsa;
}

bool RSAVerifySignature( RSA* rsa, 
                         unsigned char* MsgHash, 
                         size_t MsgHashLen, 
                         const unsigned char* Msg, 
                         size_t MsgLen, 
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
  }
}

bool verifySignature(const char *publicKey, const unsigned char *plainText,
  size_t textLength, unsigned char *signature, size_t encMessageLength) {
  RSA* publicRSA = createPublicRSA(publicKey);
  bool authentic;
  bool result = RSAVerifySignature(publicRSA, signature, encMessageLength, plainText, textLength, &authentic);
  return result & authentic;
}

char* load_file_to_buff(const char *fname) {
  FILE *fp = fopen(fname, "r");
  char *source = NULL;

  if (fp != NULL) {
      /* Go to the end of the file. */
      if (fseek(fp, 0L, SEEK_END) == 0) {
          /* Get the size of the file. */
          long bufsize = ftell(fp);
          if (bufsize == -1) {
            return NULL;
          }

          /* Allocate our buffer to that size. */
          source = malloc(sizeof(char) * (bufsize + 1));

          /* Go back to the start of the file. */
          if (fseek(fp, 0L, SEEK_SET) != 0) {
            free(source);
            return NULL;
          }

          /* Read the entire file into memory. */
          size_t newLen = fread(source, sizeof(char), bufsize, fp);
          if (ferror(fp) != 0) {
            fputs("Error reading file", stderr);
            free(source);
            return NULL;
          } else {
            source[newLen++] = '\0'; /* Just to be safe. */
          }
      }
      fclose(fp);
  }

  return source;
}

char* pubkey_from_cert(const char *cert_file) {
  EVP_PKEY *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  char *pubkey = NULL;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new(BIO_s_mem());
  BIO_set_close(outbio, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  BIO_read_filename(certbio, cert_file);
  if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_free_all(outbio);
    BIO_free_all(certbio);
    return NULL;
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pkey = X509_get_pubkey(cert)) == NULL) {
    X509_free(cert);
    BIO_free_all(outbio);
    BIO_free_all(certbio);
    return NULL;
  }

  if(!PEM_write_bio_PUBKEY(outbio, pkey)){
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(outbio);
    BIO_free_all(certbio);
    return NULL;
  }

  BIO_get_mem_data(outbio, &pubkey);
  EVP_PKEY_free(pkey);
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free(outbio);
  
  return pubkey;
}

/* int main(int argc, char const *argv[]) {
  char plainText[] = "My secret message.\n";
  char *privateKey;
  char *publicKey;
  size_t sign_len;

  privateKey = load_file_to_buff(argv[1]);
  publicKey = pubkey_from_cert(argv[2]);

  char* signature = signMessage(privateKey, plainText, &sign_len);
  bool authentic = verifySignature(publicKey, "My secret message.\n", signature, sign_len);
  if ( authentic ) {
    printf("Authentic\n");
  } else {
    printf("Not Authentic\n");
  }
  free(signature);
  return 0;
} */
