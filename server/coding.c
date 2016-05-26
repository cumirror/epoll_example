#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "buffer.h"
#include "message.h"

static uint8_t key[] = {
    '3', '.', '1', '4',
    '1', '5', '9', '2',
    '6', '5', '3', '5',
    '8', '9', '7', '9'
};

/* static buffer for encoding data */
static struct Buffer _msg;
/* static buffer for encoding data */
static struct Buffer _aes;

static char* get_pre_msg_buffer(int len) {
    if (alloc_buffer_data(&_msg, len) == 0) {
        return _msg.data;
    }

    return NULL;
}

static char* get_pre_aes_buffer(int len) {
    if (alloc_buffer_data(&_aes, len) == 0) {
        return _aes.data;
    }

    return NULL;
}

static int Base64Encode(char* input, int inlen, char* output, int* outlen) {
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    if (input == NULL || inlen <= 0 || output == NULL || *outlen <= 0) {
        return -1;
    }

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, inlen);
    BIO_ctrl(b64, BIO_CTRL_FLUSH, 0, NULL);
    BIO_get_mem_ptr(b64, &bptr);

    memcpy(output, bptr->data, bptr->length);
    *outlen = bptr->length;
    BIO_free_all(b64);
    return 0;
}

static int Base64Decode(char* input, int inlen, char* output, int* outlen) {
    BIO* b64 = NULL;
    BIO* bmem = NULL;
    int len = 0;

    if (input == NULL || inlen <= 0 || output == NULL || *outlen <= 0) {
        return -1;
    }

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(input, inlen);
    bmem = BIO_push(b64, bmem);
    len = BIO_read(bmem, output, inlen);

    *outlen = len;
    BIO_free_all(bmem);
    return 0;
}

static int aesEncrypt(char* input, int inlen, char* output, int* outlen) {
    int c_len; //length of ciphertext
    int f_len; //rest length of padded ciphertext
    EVP_CIPHER_CTX ctx;

    if (input == NULL || inlen <= 0 || output == NULL || *outlen <= 0) {
        return -1;
    }

    EVP_CIPHER_CTX_init(&ctx);

    if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        return -2;
    }

    if (EVP_EncryptUpdate(&ctx, (unsigned char*)output, &c_len, (const unsigned char*)input,
                          inlen) != 1) {
        return -3;
    }

    if (EVP_EncryptFinal_ex(&ctx, (unsigned char*)(output + c_len), &f_len) != 1) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    *outlen = c_len + f_len;
    return 0;
}

static int aesDecrypt(char* input, int inlen, char* output, int* outlen) {
    int c_len;
    int f_len;
    EVP_CIPHER_CTX ctx;

    if (input == NULL || inlen <= 0 || output == NULL || *outlen <= 0) {
        return -1;
    }

    EVP_CIPHER_CTX_init(&ctx);

    if (EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        return -2;
    }

    if (EVP_DecryptUpdate(&ctx, (unsigned char*)output, &c_len, (const unsigned char*)input,
                          inlen) != 1) {
        return -3;
    }

    if (EVP_DecryptFinal_ex(&ctx, (unsigned char*)(output + c_len), &f_len) != 1) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    *outlen = c_len + f_len;
    return 0;
}

int decoding(char* in, int inlen, char** out, int* outlen) {
    int ret;
    char* aes;
    int aes_len;
    char* msg;
    int msg_len;

    aes_len = inlen; /* base64 decode-length always smaller than encode-length */
    aes = get_pre_aes_buffer(aes_len);

    if (aes == NULL) {
        message_log(LOG_ERR, 0,
                        "get aes buffer for Base64Decode failed");
        return -1;
    }

    ret = Base64Decode(in, inlen, aes, &aes_len);

    if (ret < 0) {
        message_log(LOG_ERR, 0,
                        "Base64Decode failed ret %d", ret);
        return -2;
    }

    msg_len = aes_len;
    msg = get_pre_msg_buffer(msg_len);

    if (msg == NULL) {
        message_log(LOG_ERR, 0,
                        "get msg buffer for aesDecrypt failed");
        return -3;
    }

    ret = aesDecrypt(aes, aes_len, msg, &msg_len);

    if (ret < 0) {
        message_log(LOG_ERR, 0,
                        "aesDecrypt failed ret %d", ret);
        return -4;
    }

    *out = msg;
    *outlen = msg_len;
    return 0;
}

int encoding(char* in, int inlen, char** out, int* outlen) {
    int ret;
    char* aes;
    int aes_len;
    char* b64;
    int b64_len;

    aes_len = (inlen / 16 + 1) * 16;
    aes = get_pre_aes_buffer(aes_len);

    if (aes == NULL) {
        syslog(LOG_ERR, "get aes buffer for aesEncrypt failed\n");
        return -1;
    }

    ret = aesEncrypt(in, inlen, aes, &aes_len);

    if (ret < 0) {
        syslog(LOG_ERR, "aesEncrypt failed ret %d\n", ret);
        return -2;
    }

    b64_len = (aes_len + 2) / 3 * 4; /* max base64 encode len */
    b64 = (char*)malloc(b64_len + 4);  /* 4 bytes for length field */

    if (b64 == NULL) {
        syslog(LOG_ERR, "malloc buffer for Base64Encode failed\n");
        return -3;
    }

    ret = Base64Encode(aes, aes_len, b64 + 4, &b64_len);

    if (ret < 0) {
        syslog(LOG_ERR, "Base64Encode failed ret %d\n", ret);
        return -4;
    }

    *out = b64;
    *(int*)b64 = htonl(b64_len);
    *outlen = b64_len + 4;
    return 0;
}

#if CODING_TEST
void coding_test() {
    char* encode;
    int encode_len;
    char* decode;
    int decode_len;

    if (encoding("abcd", 4, &encode, &encode_len) < 0) {
        return ;
    }

    printf("%.*s\n", encode_len - 4, encode + 4);

    if (decoding(encode + 4, encode_len - 4, &decode, &decode_len) < 0) {
        return ;
    }

    printf("%.*s\n", decode_len, decode);

}
#endif

int init_coding() {
    init_buffer(&_msg);
    init_buffer(&_aes);

    return 0;
}
