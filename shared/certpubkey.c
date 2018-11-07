/* ------------------------------------------------------------ *
 * file:        certpubkey.c                                    *
 * purpose:     Example code to extract public keydata in certs *
 * author:      09/24/2012 Frank4DD                             *
 *                                                              *
 * gcc -o certpubkey certpubkey.c -lssl -lcrypto                *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

char* pubkey_from_cert(char *cert_file) {
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