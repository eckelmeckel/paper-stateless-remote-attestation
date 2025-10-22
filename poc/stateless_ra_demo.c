#include <endian.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* -------------------------------------------------------------------------- */
/* --- global variables ----------------------------------------------------- */
/* -------------------------------------------------------------------------- */

#define AES_GCM_KEY_LEN 32
#define AES_GCM_TAG_LEN 16
#define AES_GCM_IV_LEN 12
#define POSIX_TIME_LEN 8
#define EUI64_LEN 8
#define RANDOM_DATA_LEN 16
#define PLAINTEXT_LEN 32

/* set platform endianness */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define PLATFORM_ENDIANNESS LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define PLATFORM_ENDIANNESS BIG_ENDIAN
#else
#error Unsupported endianness
#endif

/* randomness */
static const unsigned char mbedtls_personalization[] =
        "my_random_personalization";
static const unsigned char mbedtls_personalization_len =
        sizeof(mbedtls_personalization);

/* -------------------------------------------------------------------------- */
/* --- function prototypes -------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int generate_random_bytes(const uint32_t len, uint8_t* const random_bytes);

int generate_plaintext(
        const uint8_t eui64[EUI64_LEN], uint8_t plaintext[PLAINTEXT_LEN]);

int generate_gcm_iv(
        const uint8_t plaintext[PLAINTEXT_LEN], uint8_t nonce[AES_GCM_IV_LEN]);

int aes_gcm_encrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* plaintext,
        size_t plen, uint8_t* ciphertext, uint8_t tag[AES_GCM_TAG_LEN]);

int aes_gcm_decrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* ciphertext,
        size_t clen, const uint8_t tag[AES_GCM_TAG_LEN], uint8_t* plaintext);

int chachapoly_encrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* plaintext,
        size_t plen, uint8_t* ciphertext, uint8_t tag[AES_GCM_TAG_LEN]);

int chachapoly_decrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* ciphertext,
        size_t clen, const uint8_t tag[AES_GCM_TAG_LEN], uint8_t* plaintext);

uint64_t endian_conv_uint64(const uint64_t val);

uint64_t endian_h2be_uint64(const uint64_t val);

uint64_t endian_be2h_uint64(const uint64_t val);

void print_hex(const char* label, const uint8_t* data, size_t len,
        const char* const indent);

void print_eui(const char* label, const uint8_t eui64[EUI64_LEN],
        const char* const indent);

void print_posix_time(const char* label,
        const uint8_t posix_bytes[POSIX_TIME_LEN], const char* const indent);

void print_decoded_plaintext(
        const uint8_t plaintext[PLAINTEXT_LEN], const char* const indent);

/* -------------------------------------------------------------------------- */
/* --- main function -------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

int main(void) {
    printf("\n=== Meta Information ===\n");
    char mbedtls_version[20] = {0};
    mbedtls_version_get_string(mbedtls_version);
    // mbedtls_version_get_string_full(mbedtls_version);
    printf("Mbed TLS version:      %s\n", mbedtls_version);
    printf("Mbed TLS version num:  %u\n", mbedtls_version_get_number());
    printf("\n");

    uint8_t key[AES_GCM_KEY_LEN] = {0};  // example static key

    const uint8_t eui64[EUI64_LEN] = {// Example static EUI-64
            0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01};

    /* generate plaintext */
    uint8_t plaintext[PLAINTEXT_LEN] = {0};
    generate_plaintext(eui64, plaintext);

    /* generate nonce/IV */
    uint8_t nonce[AES_GCM_IV_LEN] = {0};
    generate_gcm_iv(plaintext, nonce);

    /* ciphertext, etc. */
    uint8_t ciphertext[PLAINTEXT_LEN] = {0};
    uint8_t decrypted[PLAINTEXT_LEN] = {0};
    uint8_t tag[AES_GCM_TAG_LEN] = {0};

    /* --- AES-GCM demo ----------------------------------------------------- */

    printf("\n=== Components ===\n");
    print_decoded_plaintext(plaintext, "     ");
    print_hex("Plaintext:        ", plaintext, PLAINTEXT_LEN, "     ");

    printf("\n\n=== AES-256-GCM DEMO ===\n");
    if (aes_gcm_encrypt(
                key, nonce, plaintext, PLAINTEXT_LEN, ciphertext, tag) == 0) {
        print_hex("Ciphertext:            ", ciphertext, PLAINTEXT_LEN, "");
        print_hex("Tag:                   ", tag, AES_GCM_TAG_LEN, "");
    } else {
        printf("AES-GCM encryption failed.\n");
        return 1;
    }

    if (aes_gcm_decrypt(
                key, nonce, ciphertext, PLAINTEXT_LEN, tag, decrypted) == 0) {
        print_hex("Decrypted (Plaintext): ", decrypted, PLAINTEXT_LEN, "");
        printf("%s", "Decoded Plaintext:\n");
        print_decoded_plaintext(decrypted, "     ");
    } else {
        printf("AES-GCM decryption failed (tag mismatch).\n");
    }

    printf("\n\n=== ChaCha20-Poly1305 DEMO ===\n");
    memset(ciphertext, 0, PLAINTEXT_LEN);
    memset(decrypted, 0, PLAINTEXT_LEN);
    memset(tag, 0, AES_GCM_TAG_LEN);

    if (chachapoly_encrypt(
                key, nonce, plaintext, PLAINTEXT_LEN, ciphertext, tag) == 0) {
        print_hex("Ciphertext:            ", ciphertext, PLAINTEXT_LEN, "");
        print_hex("Tag:                   ", tag, AES_GCM_TAG_LEN, "");
    } else {
        printf("ChaCha20-Poly1305 encryption failed.\n");
        return 1;
    }

    /* --- ChaCha20-Poly1305 demo ------------------------------------------- */

    if (chachapoly_decrypt(
                key, nonce, ciphertext, PLAINTEXT_LEN, tag, decrypted) == 0) {
        print_hex("Decrypted (Plaintext): ", decrypted, PLAINTEXT_LEN, "");

        printf("%s", "Decoded Plaintext:\n");
        print_decoded_plaintext(decrypted, "     ");
    } else {
        printf("ChaCha20-Poly1305 decryption failed (tag mismatch).\n");
    }

    printf("\n");

    return 0;
}

/* -------------------------------------------------------------------------- */
/* --- function implementations --------------------------------------------- */
/* -------------------------------------------------------------------------- */

int generate_random_bytes(const uint32_t len, uint8_t* const random_bytes) {
    int ret = 0;

    /* initialize contexts */
    mbedtls_entropy_context entropy = {0};
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_context ctr_drbg = {0};
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* add seed */
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                mbedtls_personalization, mbedtls_personalization_len) != 0) {
        ret = 1;
        goto error;
    }

    /* add prediction resistance */
    mbedtls_ctr_drbg_set_prediction_resistance(
            &ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

    if (mbedtls_ctr_drbg_random(
                &ctr_drbg, (unsigned char*)random_bytes, (size_t)len) != 0) {
        ret = 1;
        goto error;
    }

error:
    /* clean up */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int generate_plaintext(
        const uint8_t eui64[EUI64_LEN], uint8_t plaintext[PLAINTEXT_LEN]) {
    const uint64_t posix_time = (uint64_t)time(NULL);
    const uint64_t posix_be = endian_h2be_uint64(posix_time);
    uint8_t posix_bytes[POSIX_TIME_LEN] = {0};
    memcpy(posix_bytes, &posix_be, sizeof(posix_be));

    /* RNG */
    uint8_t random_data[RANDOM_DATA_LEN] = {0};
    generate_random_bytes(RANDOM_DATA_LEN, random_data);

    /* compose plaintext */
    memcpy(plaintext, posix_bytes, POSIX_TIME_LEN);
    memcpy(plaintext + POSIX_TIME_LEN, eui64, EUI64_LEN);
    memcpy(plaintext + POSIX_TIME_LEN + EUI64_LEN, random_data,
            RANDOM_DATA_LEN);

    size_t used_len = POSIX_TIME_LEN + EUI64_LEN + RANDOM_DATA_LEN;
    if (used_len < PLAINTEXT_LEN) {
        memset(plaintext + used_len, 0, PLAINTEXT_LEN - used_len);
    }

    return 0;
}

int generate_gcm_iv(
        const uint8_t plaintext[PLAINTEXT_LEN], uint8_t nonce[AES_GCM_IV_LEN]) {
    unsigned char hash[32];  // SHA-256 output
    mbedtls_sha256_context ctx = {0};

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA-256, not 224
    mbedtls_sha256_update(&ctx, plaintext, PLAINTEXT_LEN);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    memcpy(nonce, hash, AES_GCM_IV_LEN);  // use first 12 bytes
    return 0;
}

int aes_gcm_encrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* plaintext,
        size_t plen, uint8_t* ciphertext, uint8_t tag[AES_GCM_TAG_LEN]) {
    mbedtls_gcm_context ctx = {0};

    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(
            &ctx, MBEDTLS_CIPHER_ID_AES, key, AES_GCM_KEY_LEN * 8);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plen, nonce,
            AES_GCM_IV_LEN, NULL, 0, plaintext, ciphertext, AES_GCM_TAG_LEN,
            tag);

    mbedtls_gcm_free(&ctx);

    return ret;
}

int aes_gcm_decrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* ciphertext,
        size_t clen, const uint8_t tag[AES_GCM_TAG_LEN], uint8_t* plaintext) {
    mbedtls_gcm_context ctx = {0};

    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(
            &ctx, MBEDTLS_CIPHER_ID_AES, key, AES_GCM_KEY_LEN * 8);

    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(&ctx, clen, nonce, AES_GCM_IV_LEN, NULL, 0,
            tag, AES_GCM_TAG_LEN, ciphertext, plaintext);

    mbedtls_gcm_free(&ctx);

    return ret;
}

int chachapoly_encrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* plaintext,
        size_t plen, uint8_t* ciphertext, uint8_t tag[AES_GCM_TAG_LEN]) {
    mbedtls_chachapoly_context ctx = {0};

    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_chachapoly_encrypt_and_tag(
            &ctx, plen, nonce, NULL, 0, plaintext, ciphertext, tag);

    mbedtls_chachapoly_free(&ctx);

    return ret;
}

int chachapoly_decrypt(const uint8_t key[AES_GCM_KEY_LEN],
        const uint8_t nonce[AES_GCM_IV_LEN], const uint8_t* ciphertext,
        size_t clen, const uint8_t tag[AES_GCM_TAG_LEN], uint8_t* plaintext) {
    mbedtls_chachapoly_context ctx = {0};

    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0)
        return ret;

    ret = mbedtls_chachapoly_auth_decrypt(
            &ctx, clen, nonce, NULL, 0, tag, ciphertext, plaintext);
    mbedtls_chachapoly_free(&ctx);

    return ret;
}

uint64_t endian_conv_uint64(const uint64_t val) {
    uint64_t swapped_val = val;
    swapped_val = ((swapped_val << 8) & 0xff00ff00ff00ff00ULL) |
                  ((swapped_val >> 8) & 0x00ff00ff00ff00ffULL);
    swapped_val = ((swapped_val << 16) & 0xffff0000ffff0000ULL) |
                  ((swapped_val >> 16) & 0x0000ffff0000ffffULL);
    return (swapped_val << 32) | (swapped_val >> 32);
}

uint64_t endian_h2be_uint64(const uint64_t val) {
#if PLATFORM_ENDIANNESS == LITTLE_ENDIAN
    return endian_conv_uint64(val);
#elif PLATFORM_ENDIANNESS == BIG_ENDIAN
    return val;
#else
#error Unsupported endianness
#endif
}

uint64_t endian_be2h_uint64(const uint64_t val) {
#if PLATFORM_ENDIANNESS == LITTLE_ENDIAN
    return endian_conv_uint64(val);
#elif PLATFORM_ENDIANNESS == BIG_ENDIAN
    return val;
#else
#error Unsupported endianness
#endif
}

void print_hex(const char* label, const uint8_t* data, size_t len,
        const char* const indent) {
    printf("%s%s", indent, label);

    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }

    printf("\n");
}

void print_eui(const char* label, const uint8_t eui64[EUI64_LEN],
        const char* const indent) {
    printf("%s%s", indent, label);

    for (size_t i = 0; i < EUI64_LEN; ++i) {
        if ((i != 0) && (i % 2 == 0)) {
            printf("%c", ':');
        }
        printf("%02X", eui64[i]);
    }

    printf("\n");
}

void print_posix_time(const char* label,
        const uint8_t posix_bytes[POSIX_TIME_LEN], const char* const indent) {
    uint64_t be_val;
    memcpy(&be_val, posix_bytes, sizeof(be_val));

    /* convert from big-endian to host byte order */
    uint64_t timestamp = endian_be2h_uint64(be_val);

    /* convert to human-readable string */
    time_t ts = (time_t)timestamp;
    struct tm* tm_info = gmtime(&ts);  // or localtime(&ts) for local timezone

    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    printf("%s%s%s (raw: %llu)\n", indent, label, buffer,
            (unsigned long long)timestamp);
}

void print_decoded_plaintext(
        const uint8_t plaintext[PLAINTEXT_LEN], const char* const indent) {

    /* POSIX time */
    print_posix_time("POSIX Time:       ", plaintext, indent);

    /* POSIX bytes */
    print_hex("POSIX Bytes (BE): ", plaintext, POSIX_TIME_LEN, indent);

    /* EUI-64 */
    print_eui("EUI-64:           ", plaintext + POSIX_TIME_LEN, indent);

    /* random data */
    print_hex("Random Data:      ", plaintext + POSIX_TIME_LEN + EUI64_LEN,
            RANDOM_DATA_LEN, indent);
}
