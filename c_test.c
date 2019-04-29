#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

const char key[] =
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIIC1DBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIXIrCqCtv6ucCAggA\n\
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECGZzcEsDZ5iQBIICgMqE6OmYJv4/\n\
TKxICGoZ3EKcTIjGxyeeYqgdbpNFWP7nP+ReX4Nw3GqWYYUt+4vuGqY2ZoMrN8yR\n\
i+c+kxktQbbw7Pbo4OdkGZ5UvsrAYnh+93MD91gYvHZTdjQjTGpUanIgLvj4t/eK\n\
albDRmPJjewH3HcdKZ4oZGS5dTCYdLXgG9bN8HBCELbCn1GQhr9TzwiPFWdTPUTe\n\
Rz4aUPy6s22U1Ku8gB/dk+uRTKOW9j+0ylqJLcOuEVjn0qLXMBXDLabipnSffocH\n\
sK4OeJPz3Um0fMPenihSaORopwK9o40trkijS++YxMRK1RTC6fNJfVr6FaRLTNLU\n\
LiStYdETRFUh4RqbX59ddwzxSbbfSues7f3vPUMDScv37GiiI25EVBW8fIAHO7NQ\n\
VLCeJ8t5cVpwjIrDqT13F3jHR8Sk+S4t56Y9teK1Cc4swz4UPZ4918cqtYsn5hMd\n\
Ea8zBl7X1ADi9iEfbyweg5AEK52spgCQtLVUGOliaRIOPZ91gNpLJetXOmeULfmi\n\
OGPK8bPfkyY5O5OFeUhd147NonKnowOCSvgtrjFlIkZv1BiTt35Xpx1nZGHEuF9k\n\
6vzJt8ne0eNjgC3avfGmhGc4jiYMJ52PuJmggdEWWaHkzcTdsFABvqO2dvj8WMxH\n\
P92nAXSuvBNvJqMQbYICSjJVgm1npuhso9wIOu/NnqcGCAJw93Pd9dJS+/yXCL6x\n\
jK+rcA0a5Q8RBo1NZnz8hzaqfABGuke/CkY/ovVKyCs0c2qsXi/zQpgvcj6l9rhK\n\
RVY6NcehXCvz9Shfx2QGaCDBptLfS5q//CnkZN7Vg/+/UQ7yK9lsNmPYSWvE3AT4\n\
1Abi+Miv2ok=\n\
-----END ENCRYPTED PRIVATE KEY-----";

const char csr[]=""
"-----BEGIN CERTIFICATE REQUEST-----\n\
MIIBlTCB/wIBATBWMQswCQYDVQQGEwJDQTELMAkGA1UECAwCQkMxEjAQBgNVBAcM\n\
CVZhbmNvdXZlcjESMBAGA1UECgwJRHluYW1zb2Z0MRIwEAYDVQQDDAlsb2NhbGhv\n\
c3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKveejYlQjO+9mPQobByYHqe\n\
e6cMuQW+qCtoLB4WkXCZGuCsA7AFgYZ/nG1wLc8PM7IHSyomKuDSq2pD+4y+AwZw\n\
cbIzDW5fEtYXakeTnn93DX3JvFeUa8poC5rypRKEw6cxrWIBDKsBf939epxI+ueb\n\
7c8E+qbACTB7B++VPdUJAgMBAAGgADANBgkqhkiG9w0BAQsFAAOBgQCjSvbKpeg4\n\
NwkFKM9xjbj2O9fRaWHAe6dg6e68tFOkT6VzMTdIQnVhKBfoaBuJE5myrAv+ZymU\n\
2jPaqkaoUe1urtuoLKWuIMc3HzTW1Z6n7++BOMvOm6X2ygqppQOzXFFfGQJ0z0jZ\n\
v+py3cAokqfgmTZe0mBvvdMEgjPMKkxM+w==\n\
-----END CERTIFICATE REQUEST-----";

const char ca_crt[] =
"-----BEGIN CERTIFICATE-----\n\
MIICQTCCAaqgAwIBAgIBADANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJDQTEL\n\
MAkGA1UECAwCQkMxEjAQBgNVBAcMCVZhbmNvdXZlcjESMBAGA1UECgwJRHluYW1z\n\
b2Z0MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTkwNDI2MjIzODUxWhcNMjAwNDI1\n\
MjIzODUxWjBWMQswCQYDVQQGEwJDQTELMAkGA1UECAwCQkMxEjAQBgNVBAcMCVZh\n\
bmNvdXZlcjESMBAGA1UECgwJRHluYW1zb2Z0MRIwEAYDVQQDDAlsb2NhbGhvc3Qw\n\
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKveejYlQjO+9mPQobByYHqee6cM\n\
uQW+qCtoLB4WkXCZGuCsA7AFgYZ/nG1wLc8PM7IHSyomKuDSq2pD+4y+AwZwcbIz\n\
DW5fEtYXakeTnn93DX3JvFeUa8poC5rypRKEw6cxrWIBDKsBf939epxI+ueb7c8E\n\
+qbACTB7B++VPdUJAgMBAAGjHzAdMBsGA1UdEQQUMBKCBmVjbi5pb4IIKi5lY24u\n\
aW8wDQYJKoZIhvcNAQELBQADgYEAHqpZlflmK6fQt2kmoJ+JP0RwTe5yBF6cZPaa\n\
bXsz1oA7GZvlfBgUoIxBZaHzZuE48dygt5dG3ub9EVIf4ErapIqqh9C9u9mIoq5S\n\
L9tj+BJ5CWhEIRvNYDinl1OcoHCEaVYGisG6bCtVPmlY7P+W81+5fj9F5EYqIkeA\n\
Jrhdhso=\n\
-----END CERTIFICATE-----";

void err_descr_to_stderr(const char *err_patern) {
	char buffer[120];
	ERR_error_string(ERR_get_error(), buffer);
	fprintf(stderr, "%s due to: %s\n", err_patern, buffer);
}

void init_crypto() {
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
}

BIO * csr_crt(const char * key, const char * csr, const char * ca_crt) {
	BIO * buff = NULL;

	// load pkey
	char *password = "replace_me";
	BIO *pkeybio = BIO_new_mem_buf(key, strlen(key));
	RSA *rsa = PEM_read_bio_RSAPrivateKey(pkeybio, NULL, NULL, password);
	if (rsa == NULL) {
		err_descr_to_stderr("Failed to create key bio");
		goto __error;
	}

	// 4. set public key of x509 req
	EVP_PKEY *pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, rsa);

	// load pca
	BIO *cacertbio = BIO_new_mem_buf(ca_crt, strlen(ca_crt));
	X509 *cacert = PEM_read_bio_X509(cacertbio, NULL, NULL, NULL);

	// load csr
	/* ---------------------------------------------------------- *
	 * Load the request data in a BIO, then in a x509_REQ struct. *
	 * ---------------------------------------------------------- */
	BIO *reqbio = BIO_new_mem_buf(csr, strlen(csr));
	X509_REQ *certreq = NULL;
	if (! (certreq = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL))) {
		err_descr_to_stderr("Error can't read X509 request data into memory");
		goto __error;
	}

	// create certificate
	/* --------------------------------------------------------- *
	 * Build Certificate with data from request                  *
	 * ----------------------------------------------------------*/
	X509 *newcert = X509_new();
	if (newcert == NULL) {
		err_descr_to_stderr("Error creating new X509 object");
		goto __error;
	}

	if (X509_set_version(newcert, 2) != 1) {
		err_descr_to_stderr("Error setting certificate version");
		goto __error;
	}

	if (X509_set_pubkey(newcert, pKey) != 1) {
		err_descr_to_stderr("X509_set_pubkey");
		goto __error;
	}

	ASN1_INTEGER  *aserial = NULL;
	aserial=ASN1_INTEGER_new();
	ASN1_INTEGER_set(aserial, 0);
	if (! X509_set_serialNumber(newcert, aserial)) {
		err_descr_to_stderr("Error setting serial number of the certificate");
		goto __error;
	}
	ASN1_INTEGER_free(aserial);

	/* --------------------------------------------------------- *
	 * Extract the subject name from the request                 *
	 * ----------------------------------------------------------*/
	X509_NAME *name = X509_REQ_get_subject_name(certreq);
	if (name == NULL) {
		err_descr_to_stderr("Error getting subject from cert request");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Set the new certificate subject name                      *
	 * ----------------------------------------------------------*/
	if (X509_set_subject_name(newcert, name) != 1) {
		err_descr_to_stderr("Error setting subject name of certificate");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Extract the subject name from the signing CA cert         *
	 * ----------------------------------------------------------*/
	name = X509_get_subject_name(cacert);
	if (name == NULL) {
		err_descr_to_stderr("Error getting subject from CA certificate");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Set the new certificate issuer name                       *
	 * ----------------------------------------------------------*/
	if (X509_set_issuer_name(newcert, name) != 1) {
		err_descr_to_stderr("Error setting issuer name of certificate");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Extract the public key data from the request              *
	 * ----------------------------------------------------------*/
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(certreq);
	if (req_pubkey == NULL) {
		err_descr_to_stderr("Error unpacking public key from request");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Optionally: Use the public key to verify the signature    *
	 * ----------------------------------------------------------*/
	if (X509_REQ_verify(certreq, req_pubkey) != 1) {
		err_descr_to_stderr("Error verifying signature on request");
		goto __error;
	}

	/* --------------------------------------------------------- *
	 * Set the new certificate public key                        *
	 * ----------------------------------------------------------*/
	if (X509_set_pubkey(newcert, req_pubkey) != 1) {
		err_descr_to_stderr("Error setting public key of certificate");
		goto __error;
	}

	/* ---------------------------------------------------------- *
	 * Set X509V3 start date (now) and expiration date (+365 days)*
	 * -----------------------------------------------------------*/
	if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
		err_descr_to_stderr("Error setting start time");
		goto __error;
	}

	long valid_secs = 31536000;

	if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
		err_descr_to_stderr("Error setting expiration time");
		goto __error;
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
	EVP_MD const *digest = NULL;
	digest = EVP_sha256();

	if (! X509_sign(newcert, pKey, digest)) {
		err_descr_to_stderr("Error signing the new certificate");
		goto __error;
	}

	/* ------------------------------------------------------------ *
	 *  print the certificate                                       *
	 * -------------------------------------------------------------*/
	buff = BIO_new(BIO_s_mem());
	if (! PEM_write_bio_X509(buff, newcert)) {
		err_descr_to_stderr("Error printing the signed certificate");
		goto __error;
	}

	// create data buffer and return it
	//BIO_get_mem_ptr(outbio, &buff);
	//BIO_set_close(outbio, BIO_NOCLOSE);

__error:
	// private key and buffer free
	if (pkeybio) BIO_free(pkeybio);
	if (pKey) EVP_PKEY_free(pKey);

	// CA certificate, CA pub key and buffer free
	if (cacertbio) BIO_free(cacertbio);
	if (cacert) X509_free(cacert);
	if (req_pubkey)	EVP_PKEY_free(req_pubkey);

	// CSR and buffer free
	if (reqbio)	BIO_free(reqbio);
	if (certreq) X509_REQ_free(certreq);

	if (newcert) X509_free(newcert);

	//if (outbio)	BIO_free(outbio);

	return buff;
}

int main() {
	for (uint idx = 0; idx < 10; idx++) {
		BUF_MEM *data_ptr = NULL;
		BIO * data = csr_crt(key, csr, ca_crt);

		if (data != NULL) {
			BIO_get_mem_ptr(data, &data_ptr);
			if (data_ptr != NULL) {
				printf("CRT: \n");
				for (uint idx = 0; idx < data_ptr->length; idx++) {
					printf("%c", data_ptr->data[idx]);
				}
			}
			BIO_free(data);
		}
	}
}

