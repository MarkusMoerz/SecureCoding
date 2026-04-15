#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UPDATE_FILE "software_update.bin"
#define SIG_FILE "software_update.sig"
#define CERT_FILE "software_update.crt"
#define ROOT_CA_FILE "rootCA.crt"
#define CHECKSUM_FILE "software_update.checksum"

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void verify_certificate() {
    FILE *cert_fp = fopen(CERT_FILE, "r");
    FILE *ca_fp = fopen(ROOT_CA_FILE, "r");

    if (!cert_fp || !ca_fp) {
        perror("Error opening certificate files");
        exit(EXIT_FAILURE);
    }

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    X509 *ca = PEM_read_X509(ca_fp, NULL, NULL, NULL);

    if (!cert || !ca) handle_openssl_error();

    EVP_PKEY *ca_pubkey = X509_get_pubkey(ca);

    if (X509_verify(cert, ca_pubkey) != 1) {
        printf("Certificate verification failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Certificate verified successfully\n");

    EVP_PKEY_free(ca_pubkey);
    X509_free(cert);
    X509_free(ca);
    fclose(cert_fp);
    fclose(ca_fp);
}

void verify_signature() {
    FILE *cert_fp = fopen(CERT_FILE, "r");
    FILE *sig_fp = fopen(SIG_FILE, "rb");
    FILE *data_fp = fopen(UPDATE_FILE, "rb");

    if (!cert_fp || !sig_fp || !data_fp) {
        perror("Error opening files for signature verification");
        exit(EXIT_FAILURE);
    }

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    if (!cert || !pubkey) handle_openssl_error();

    // Read signature
    fseek(sig_fp, 0, SEEK_END);
    long sig_len = ftell(sig_fp);
    rewind(sig_fp);

    unsigned char *sig = malloc(sig_len);
    fread(sig, 1, sig_len, sig_fp);

    // Initialize verification
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) handle_openssl_error();

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0)
        handle_openssl_error();

    // Read file and update digest
    unsigned char buffer[4096];
    size_t len;
    while ((len = fread(buffer, 1, sizeof(buffer), data_fp)) > 0) {
        if (EVP_DigestVerifyUpdate(md_ctx, buffer, len) <= 0)
            handle_openssl_error();
    }

    // Verify signature
    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);

    if (result == 1) {
        printf("Signature verified successfully\n");
    } else {
        printf("Signature verification failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pubkey);
    X509_free(cert);
    fclose(cert_fp);
    fclose(sig_fp);
    fclose(data_fp);
    free(sig);
}

void verify_checksum() {
    FILE *file = fopen(UPDATE_FILE, "rb");
    FILE *checksum_fp = fopen(CHECKSUM_FILE, "r");

    if (!file || !checksum_fp) {
        perror("Error opening files for checksum verification");
        exit(EXIT_FAILURE);
    }

    char expected_checksum[65];
    fscanf(checksum_fp, "%64s", expected_checksum);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);

    unsigned char buffer[4096];
    size_t len;

    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(md_ctx, buffer, len);
    }

    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);

    char computed_checksum[65];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&computed_checksum[i * 2], "%02x", hash[i]);
    }

    if (strncmp(expected_checksum, computed_checksum, 64) == 0) {
        printf("Checksum verified successfully\n");
    } else {
        printf("Checksum mismatch\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(md_ctx);
    fclose(file);
    fclose(checksum_fp);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Verifying software update...\n\n");

    verify_certificate();
    verify_signature();
    verify_checksum();

    printf("\nUpdate is VALID and trusted!\n");

    return 0;
}