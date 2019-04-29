/*
// https://en.wikibooks.org/wiki/OpenSSL/Error_handling
// https://riptutorial.com/Download/openssl.pdf
// https://zakird.com/2013/10/13/certificate-parsing-with-openssl
// http://fm4dd.com/openssl/certcreate.htm
// http://fm4dd.com/openssl/certrenewal.htm
// https://security.stackexchange.com/questions/184845/how-to-generate-csrcertificate-signing-request-using-c-and-openssl
// https://curl.haxx.se/libcurl/c/usercertinmem.html
// https://doginthehat.com.au/2014/04/basic-openssl-rsa-encryptdecrypt-example-in-cocoa/
// www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c
// http://fm4dd.com/openssl/manual-ssl/
// http://fm4dd.com/openssl/pkcs12test.htm
// https://github.com/openssl/openssl/blob/master/test/v3nametest.c
// https://www.sslshopper.com/article-most-common-openssl-commands.html
// https://wiki.openssl.org/index.php/Main_Page
// https://ecn.io/pragmatically-generating-a-self-signed-certificate-and-private-key-using-openssl-d1753528e3d2
*/

#define LUA_LIB
#define _GNU_SOURCE

#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#if LUA_VERSION_NUM < 502
#define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#define luaL_setfuncs(L,l,n) (assert(n==0), luaL_register(L,NULL,l))
#define luaL_checkunsigned(L,n) luaL_checknumber(L,n)
#endif

#if LUA_VERSION_NUM >= 503
#ifndef luaL_checkunsigned
#define luaL_checkunsigned(L,n) ((lua_Unsigned)luaL_checkinteger(L,n))
#endif
#endif

#ifdef NO_CHECK_UDATA
#define checkudata(L,i,tname) lua_touserdata(L, i)
#else
#define checkudata(L,i,tname) luaL_checkudata(L, i, tname)
#endif

#define lua_boxpointer(L,u) \
    (*(void **) (lua_newuserdata(L, sizeof(void *))) = (u))

#define lua_unboxpointer(L,i,tname) \
    (*(void **) (checkudata(L, i, tname)))

/* Max Lua arguments for function */
#define MAXVARS 200


int gen_rsa_key(lua_State *L) {

  EVP_PKEY *pkey = NULL;
  RSA *rsa = NULL;
  BIGNUM *bn = NULL;
  BIO *bio = NULL;

  unsigned int kBits = 0;
  char *buf = NULL;

  const int argc = lua_gettop(L);
  if (argc < 1) {
    fprintf(stderr, "you must pass one argument: bits !\n");
    return 0;
  }
  if (luaL_checkinteger(L, 1) < 0) {
    fprintf(stderr, "first argument must be positive integer!\n");
    return 0;
  }
  kBits = (unsigned int) luaL_checkint(L, 1);

  pkey = EVP_PKEY_new();
  rsa = RSA_new();
  bn = BN_new();
  BN_set_word(bn, RSA_F4);
  RSA_generate_key_ex(rsa, kBits, bn, NULL);
  EVP_PKEY_assign_RSA(pkey, rsa);
  rsa = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

  bio = BIO_new(BIO_s_mem());

  PEM_write_bio_PrivateKey(
     bio,
     pkey,
     EVP_des_ede3_cbc(),
     "replace_me",        /* replace_me */
     10,                  /* 10 */
     NULL,                /* callback for requesting a password */
     NULL                 /* data to pass to the callback */
  );

  size_t len = BIO_get_mem_data (bio, &buf);
  char *rret = (char *) calloc (1, 1 + len);
  if (rret) {
    memcpy (rret, buf, len);
  }

  lua_pushlstring(L, rret, len + 1);

  BIO_free_all(bio);
  EVP_PKEY_free(pkey);
  free(rret);
  BN_free(bn);

  return 1;
}

int gen_csr(lua_State *L) {

  unsigned int argc = lua_gettop(L);
  if (argc < 1) {
    fprintf(stderr, "you must pass one argument: priv key!\n");
    return 0;
  }
  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be string: private key!\n");
    return 0;
  }
  size_t pkey_len = 0;
  const char *pkey = luaL_checklstring(L, 1, &pkey_len);
  if (pkey_len == 0) {
    fprintf(stderr, "pkey length should greater then zero!\n");
    return 0;
  }

  unsigned char *password = "replace_me";

  RSA *rsa     = NULL;
  BIO *pkeybio = NULL;

  pkeybio = BIO_new_mem_buf(pkey, pkey_len);

  rsa = PEM_read_bio_RSAPrivateKey (pkeybio, NULL, 0, password);
  if (rsa == NULL) {
    fprintf(stderr, "Failed to create key bio!\n");
    return 0;
  }

  // set public key of x509 req
  EVP_PKEY *pKey = EVP_PKEY_new();;
  EVP_PKEY_assign_RSA(pKey, rsa);
  rsa = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

  // declare
  int ret;
  int nVersion = 1;
  X509_REQ *x509_req   = NULL;
  X509_NAME *x509_name = NULL;
  BIO *out             = NULL;
  char *buf            = NULL;

  // csr info
  const char *szCountry      = "CA";
  const char *szProvince     = "BC";
  const char *szCity         = "Vancouver";
  const char *szOrganization = "Dynamsoft";
  const char *szCommon       = "localhost";

  // 2. set version of x509 req
  x509_req = X509_REQ_new();
  ret = X509_REQ_set_version(x509_req, nVersion);
  if (ret != 1) {
    fprintf(stderr, "X509_REQ_set_version ret != 1!\n");
    return 0;
  }

  // 3. set subject of x509 req
  x509_name = X509_REQ_get_subject_name(x509_req);
  ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
  if (ret != 1){
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
  if (ret != 1){
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
  if (ret != 1){
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
  if (ret != 1){
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
  if (ret != 1){
    return 0;
  }

  ret = X509_REQ_set_pubkey(x509_req, pKey);
  if (ret != 1){
    return 0;
  }

  // 5. set sign key of x509 req
  ret = X509_REQ_sign(x509_req, pKey, EVP_sha256());    // return x509_req->signature->length // sha256
  if (ret <= 0){
    return 0;
  }

  out = BIO_new(BIO_s_mem());
  ret = PEM_write_bio_X509_REQ(out, x509_req);

  const size_t len = BIO_get_mem_data (out, &buf);
  char *rret = (char *) calloc (1, 1 + len);
  if (rret) {
    memcpy (rret, buf, len);
  }
  lua_pushlstring(L, rret, len + 1);

  EVP_PKEY_free(pKey);
  BIO_free_all(pkeybio);

  X509_REQ_free(x509_req);
  BIO_free_all(out);

  free(rret);

  return 1;
}

int gen_crt(lua_State *L) {

  const unsigned int argc = lua_gettop(L);
  if (argc < 1) {
    fprintf(stderr, "you must pass one argument: (priv_key, csr)!\n");
    return 0;
  }
  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be string: private key!\n");
    return 0;
  }
  size_t pkey_len = 0;
  const char *pkey = luaL_checklstring(L, 1, &pkey_len);
  if (pkey_len == 0) {
    fprintf(stderr, "pkey length should greater then zero!\n");
    return 0;
  }

  // load pkey
  unsigned char *password = "replace_me";
  RSA *rsa     = NULL;
  BIO *pkeybio = NULL;
  pkeybio = BIO_new_mem_buf(pkey, pkey_len);
  rsa = PEM_read_bio_RSAPrivateKey(pkeybio, NULL, 0, password);
  if (rsa == NULL) {
    fprintf(stderr, "Failed to create key bio!\n");
    return 0;
  }

  EVP_PKEY *pKey = NULL;

  // 4. set public key of x509 req
  pKey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pKey, rsa);
  rsa = NULL;   // will be free rsa when EVP_PKEY_free(pKey)



  // create cert
  X509 *newcert = NULL;


  /* --------------------------------------------------------- *
   * Build Certificate with data from request                  *
   * ----------------------------------------------------------*/
  if (! (newcert=X509_new())) {
    fprintf(stderr, "Error creating new X509 object\n");
    return 0;
  }

  if (X509_set_version(newcert, 2) != 1) {
    fprintf(stderr, "Error setting certificate version\n");
    return 0;
  }

  if (X509_set_pubkey(newcert, pKey) != 1) {
    fprintf(stderr, "X509_set_pubkey\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * set the certificate serial number here                    *
   * If there is a problem, the value defaults to '0'          *
   * ----------------------------------------------------------*/

  ASN1_INTEGER  *aserial = NULL;

  aserial=ASN1_INTEGER_new();
  ASN1_INTEGER_set(aserial, 0);
  if (! X509_set_serialNumber(newcert, aserial)) {
    fprintf(stderr, "Error setting serial number of the certificate\n");
    return 0;
  }

  const char      *szCountry = "CA";
  const char      *szProvince = "BC";
  const char      *szCity = "Vancouver";
  const char      *szOrganization = "Dynamsoft";
  const char      *szCommon = "localhost";

  X509_NAME *x509_name = NULL;

  /* X509_REQ *x509_req = NULL; */
  /* // 2. set version of x509 req */
  /* x509_req = X509_REQ_new(); */
  /* int nVersion = 1; */
  int ret;
  /* ret = X509_REQ_set_version(x509_req, nVersion); */
  /* if (ret != 1) { */
  /*   fprintf(stderr, "X509_REQ_set_version ret != 1!\n"); */
  /*   return 0; */
  /* } */



  /* ---------------------------------------------------------- *
   * Set X509V3 start date (now) and expiration date (+365 days)*
   * -----------------------------------------------------------*/
   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
      fprintf(stderr, "Error setting start time\n");
      return 0;
   }

   long valid_secs = 31536000;
   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
     fprintf(stderr, "Error setting expiration time\n");
      return 0;
   }

  // x509_name = X509_REQ_get_subject_name(x509_req);
  x509_name = X509_get_subject_name(newcert);
  ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
  if (ret != 1){
    fprintf(stderr, "1 \n");
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
  if (ret != 1){
    fprintf(stderr, "2 \n");
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
  if (ret != 1){
    fprintf(stderr, "3 \n");
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
  if (ret != 1){
    fprintf(stderr, "4 \n");
    return 0;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
  if (ret != 1){
    fprintf(stderr, "5 \n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Set the new certificate subject name                      *
   * ----------------------------------------------------------*/
  /* if (X509_set_subject_name(newcert, x509_name) != 1) { */
  /*   fprintf(stderr, "Error setting subject name of certificate\n"); */
  /*   return 0; */
  /*  } */

  /* --------------------------------------------------------- *
   * Set the new certificate issuer name                       *
   * ----------------------------------------------------------*/
  if (X509_set_issuer_name(newcert, x509_name) != 1) {
    fprintf(stderr, "Error setting issuer name of certificate\n");
    return 0;
  }

  // Modern browsers ignore the CN subject field and refer only to the Subject
  // Alternative Name extension, which allows you to specify
  // multiple domain names, IP addresses, and more for a single certificate.
  // The SAN value is in the following format:
  // <TYPE>.<INDEX>:<VALUE>
  // Common types are:
  // - DNS
  // - IP
  // - email
  // - URI
  // Join multiple SAN entries using a comma.
  // In this example, this certificate is for both the `ecn.io` and `*.ecn.io`
  // domains. Which means it'll cover all single level subdomains for ecn.io
  // (E.G. blog.ecn.io but not awesome.blog.ecn.io)
  const char * san_value = "DNS.1:ecn.io,DNS.2:*.ecn.io";

  X509_EXTENSION * extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_value);
  if (X509_add_ext(newcert, extension, -1) == 0) {
    // OpenSSL Error. Use `ERR_peek_last_error_line` to find out more.
    X509_EXTENSION_free(extension);
    return 0;
  }
  X509_EXTENSION_free(extension);


   /* ----------------------------------------------------------- *
   * Set digest type, sign new certificate with CA's private key *
   * ------------------------------------------------------------*/
   EVP_MD const *digest = NULL;
   digest = EVP_sha256();

   if (! X509_sign(newcert, pKey, digest)) {
     fprintf(stderr, "Error signing the new certificate\n");
     return 0;
   }


   /* ------------------------------------------------------------ *
    *  print the certificate                                       *
    * -------------------------------------------------------------*/
   BIO  *outbio = NULL;
   outbio = BIO_new(BIO_s_mem());

   if (! PEM_write_bio_X509(outbio, newcert)) {
     fprintf(stderr, "Error printing the signed certificate\n");
     return 0;
   }

   char *buf = NULL;

  size_t len = BIO_get_mem_data (outbio, &buf);
   char *rret = (char *) calloc (1, 1 + len);
   if (rret) {
     memcpy (rret, buf, len);
   }
   lua_pushlstring(L, rret, len + 1);

   free(rret);

  /*  // free pkey */
  /* free(rsa); */
  BIO_free_all(pkeybio);
  EVP_PKEY_free(pKey);

  // free cert
  X509_free(newcert);
  ASN1_INTEGER_free (aserial);

  BIO_free_all(outbio);
  /* // X509_NAME_free(x509_name); */

  return 1;
}


int csr_crt(lua_State *L) {

  unsigned int argc = lua_gettop(L);
  if (argc < 3) {
    fprintf(stderr, "you must pass one argument: (priv_key, csr)!\n");
    return 0;
  }

  if (lua_isstring(L, 1) != 1) {
    fprintf(stderr, "first argument must be string: private key!\n");
    return 0;
  }
  size_t pkey_len = 0;
  const char *pkey = luaL_checklstring(L, 1, &pkey_len);
  if (pkey_len == 0) {
    fprintf(stderr, "pkey length should greater then zero!\n");
    return 0;
  }

  if (lua_isstring(L, 2) != 1) {
    fprintf(stderr, "second argument must be string: crt!\n");
    return 0;
  }
  size_t crt_len = 0;
  const char *crt = luaL_checklstring(L, 2, &crt_len);
  if (crt_len == 0) {
    fprintf(stderr, "crt length should greater then zero!\n");
    return 0;
  }

  if (lua_isstring(L, 3) != 1) {
    fprintf(stderr, "third argument must be string: csr!\n");
    return 0;
  }
  size_t csr_len = 0;
  const char *csr = luaL_checklstring(L, 3, &csr_len);
  if (csr_len == 0) {
    fprintf(stderr, "csr length should greater then zero!\n");
    return 0;
  }

  // printf("\n%s\n%s\n%s\n", pkey, crt, csr);


  // load pkey
  char *password = "replace_me";

  BIO *pkeybio = BIO_new_mem_buf(pkey, pkey_len);
  RSA *rsa = PEM_read_bio_RSAPrivateKey(pkeybio, NULL, 0, password);
  if (rsa == NULL) {
    fprintf(stderr, "Failed to create key bio!\n");
    return 0;
  }

  // 4. set public key of x509 req
  EVP_PKEY *pKey = EVP_PKEY_new();;
  EVP_PKEY_assign_RSA(pKey, rsa);
  rsa = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

  // load pca
  BIO *cacertbio = BIO_new_mem_buf(crt, crt_len);
  X509 *cacert = PEM_read_bio_X509(cacertbio, NULL, NULL, NULL);

  // load csr
  /* ---------------------------------------------------------- *
   * Load the request data in a BIO, then in a x509_REQ struct. *
   * ---------------------------------------------------------- */
  BIO *reqbio = BIO_new_mem_buf(csr, csr_len);
  X509_REQ *certreq = NULL;
  if (! (certreq = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL))) {
    fprintf(stderr, "Error can't read X509 request data into memory\n");
    return 0;
  }

  // create cert
  X509 *newcert = NULL;

  /* --------------------------------------------------------- *
   * Build Certificate with data from request                  *
   * ----------------------------------------------------------*/
  if (! (newcert=X509_new())) {
    fprintf(stderr, "Error creating new X509 object\n");
    return 0;
  }

  if (X509_set_version(newcert, 2) != 1) {
    fprintf(stderr, "Error setting certificate version\n");
    return 0;
  }

  if (X509_set_pubkey(newcert, pKey) != 1) {
    fprintf(stderr, "X509_set_pubkey\n");
    return 0;
  }

  ASN1_INTEGER  *aserial = NULL;
  aserial=ASN1_INTEGER_new();
  ASN1_INTEGER_set(aserial, 0);
  if (! X509_set_serialNumber(newcert, aserial)) {
    fprintf(stderr, "Error setting serial number of the certificate\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Extract the subject name from the request                 *
   * ----------------------------------------------------------*/
  X509_NAME *name;
  if (! (name = X509_REQ_get_subject_name(certreq))) {
    fprintf(stderr, "Error getting subject from cert request\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Set the new certificate subject name                      *
   * ----------------------------------------------------------*/
  if (X509_set_subject_name(newcert, name) != 1) {
    fprintf(stderr, "Error setting subject name of certificate\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Extract the subject name from the signing CA cert         *
   * ----------------------------------------------------------*/
  if (! (name = X509_get_subject_name(cacert))) {
    fprintf(stderr, "Error getting subject from CA certificate\n");
    return 0;
   }

   /* --------------------------------------------------------- *
   * Set the new certificate issuer name                       *
   * ----------------------------------------------------------*/
  if (X509_set_issuer_name(newcert, name) != 1) {
    fprintf(stderr, "Error setting issuer name of certificate\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Extract the public key data from the request              *
   * ----------------------------------------------------------*/
  EVP_PKEY *req_pubkey;
  if (! (req_pubkey=X509_REQ_get_pubkey(certreq))) {
    fprintf(stderr, "Error unpacking public key from request\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Optionally: Use the public key to verify the signature    *
   * ----------------------------------------------------------*/
  if (X509_REQ_verify(certreq, req_pubkey) != 1) {
    fprintf(stderr, "Error verifying signature on request\n");
    return 0;
  }

  /* --------------------------------------------------------- *
   * Set the new certificate public key                        *
   * ----------------------------------------------------------*/
  if (X509_set_pubkey(newcert, req_pubkey) != 1) {
    fprintf(stderr, "Error setting public key of certificate\n");
    return 0;
  }


  /* ---------------------------------------------------------- *
   * Set X509V3 start date (now) and expiration date (+365 days)*
   * -----------------------------------------------------------*/
   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
     fprintf(stderr, "Error setting start time\n");
     return 0;
   }

   long valid_secs = 31536000;

   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
      fprintf(stderr, "Error setting expiration time\n");
      return 0;
   }

  /* ----------------------------------------------------------- *
   * Add X509V3 extensions                                       *
   * ------------------------------------------------------------*/
   X509V3_CTX                   ctx;
   X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
   // X509_EXTENSION *ext;

   /* ----------------------------------------------------------- *
   * Set digest type, sign new certificate with CA's private key *
   * ------------------------------------------------------------*/
   EVP_MD                       const *digest = NULL;
   digest = EVP_sha256();

   if (! X509_sign(newcert, pKey, digest)) {
     fprintf(stderr, "Error signing the new certificate\n");
     return 0;
   }



   /* ------------------------------------------------------------ *
    *  print the certificate                                       *
    * -------------------------------------------------------------*/
   BIO  *outbio = NULL;
   outbio = BIO_new(BIO_s_mem());

   if (! PEM_write_bio_X509(outbio, newcert)) {
     fprintf(stderr, "Error printing the signed certificate\n");
     return 0;
   }

   char *buf = NULL;
   size_t len = BIO_get_mem_data (outbio, &buf);
   char *rret = (char *) calloc (1, 1 + len);
   if (rret) {
     memcpy (rret, buf, len);
   }
   lua_pushlstring(L, rret, len + 1);


  BIO_free_all(pkeybio);
  EVP_PKEY_free(pKey);

  BIO_free_all(cacertbio);
  X509_free(cacert);

  BIO_free_all(reqbio);
  X509_REQ_free(certreq);

  X509_free(newcert);

  ASN1_INTEGER_free(aserial);

  // X509_NAME_free(name);

  EVP_PKEY_free(req_pubkey);

  BIO_free_all(outbio);


  free(rret);

  /*  // -- free */
  /*  BIO_free_all(pkeybio); */
  /*   */
  /*  BIO_free_all(outbio); */

  /*  EVP_PKEY_free(pKey); */
  /*   */

  /*  X509_REQ_free(certreq); */
  /*  X509_free(newcert); */

   /* free(pkey); */
   /* free(crt); */
   /* free(csr); */

   // -- end free

   return 1;
}

// Register library using this array
static const struct luaL_Reg OpenSSLLib[] = {
    {"gen_rsa_key", gen_rsa_key},
    {"gen_csr", gen_csr},
    {"gen_crt", gen_crt},
    {"csr_crt", csr_crt},
    {NULL, NULL}
};

// LUALIB_API int luaopen_openssl_core(lua_State *L) {
LUALIB_API int luaopen_core(lua_State *L) {
  luaL_newlib(L, OpenSSLLib);
  return 1;
}
