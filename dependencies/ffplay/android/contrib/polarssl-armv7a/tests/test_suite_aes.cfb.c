#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/aes.h>

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 * 
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += (((info->v1 << 4) ^ (info->v1 >> 5)) + info->v1) ^ (sum + k[sum & 3]);
            sum += delta;
            info->v1 += (((info->v0 << 4) ^ (info->v0 >> 5)) + info->v0) ^ (sum + k[(sum>>11) & 3]);
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}


FCT_BGN()
{
#ifdef POLARSSL_AES_C


    FCT_SUITE_BGN(test_suite_aes)
    {
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "970014d634e2b7650777e8e84d03ccd8" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f17e79aed0db7e279e955b5f493875a7" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fc000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "9ed5a75136a940d0963da379db4af26a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "64cf9c7abc50b888af65f49d521944b2" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f7efc89d5dba578104016ce5ad659c05" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "47d6742eefcc0465dc96355e851b64d9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "0306194f666d183624aa230a8b264ae7" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3eb39790678c56bee34bbcdeccf6cdb5" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "858075d536d79ccee571f7d7204b1f67" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "6a118a874519e64e9963798a503f1d35" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "dc43be40be0e53712f7e2bf5ca707209" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "cb9fceec81286ca3e989bd979b0cb284" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "92beedab1895a94faa69b632e5cc47ce" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "b26aeb1874e47ca8358ff22378f09144" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "459264f4798f6a78bacb89c15ed3d601" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffff0" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f9b0fda0c4a898f5b9e6f661c4ce4d07" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffff8" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "8ade895913685c67c5269f8aae42983e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffffc" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "39bde67d5c8ed8a8b1c37eb8fa9f5ac0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffe000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "1114bc2028009b923f0b01915ce5e7c4" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffff000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "9c28524a16a1e1c1452971caa8d13476" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffff800000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ed62e16363638360fdd6ad62112794f0" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3071a2a48fe6cbd04f1a129098e308f8" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "4b98e06d356deb07ebb824e5713f7be3" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90f42ec0f68385f2ffc5dfc03a654dce" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "7a20a53d460fc9ce0423a7a0764c6cf2" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "febd9a24d8b65c1c787d50a4ed3619a9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "f4a70d8af877f9b02b4c40df57d45b17" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
            unhexify( src_str, "0336763e966d92595a567cc9ce537f5e" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "9798c4640bad75c7c3227db910174e72" );
            unhexify( src_str, "a9a1631bf4996954ebc093957b234589" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "96ab5c2ff612d9dfaae8c31f30c42168" );
            unhexify( src_str, "ff4f8391a6a40ca5b25d23bedd44a597" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffff0000000000000000" );
            unhexify( src_str, "f807c3e7985fe0f5a50e2cdb25c5109e" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffff8000000000000000" );
            unhexify( src_str, "41f992a856fb278b389a62f5d274d7e9" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffc000000000000000" );
            unhexify( src_str, "10d3ed7a6fe15ab4d91acbc7d0767ab1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffc0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "8dfd999be5d0cfa35732c0ddc88ff5a5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffe0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "02647c76a300c3173b841487eb2bae9f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffff0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "172df8b02f04b53adab028b4e01acd87" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "d184c36cf0dddfec39e654195006022237871a47c33d3198" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "2e19fb60a3e1de0166f483c97824a978" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "7656709538dd5fec41e0ce6a0f8e207d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "a67cf333b314d411d3c0ae6e1cfcd8f5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "9c2d8842e5f48f57648205d39a239af1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "c9b8135ff1b5adc413dfd053b21bd96d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "bff52510095f518ecca60af4205444bb" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "4a3650c3371ce2eb35e389a171427440" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "51719783d3185a535bd75adc65071ce1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffe00000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f34e4a6324ea4a5c39a661c8fe5ada8f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffff00000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "0882a16f44088d42447a29ac090ec17e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffff80000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "3a3c15bfc11a9537c130687004e136ee" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffe00000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "60136703374f64e860b48ce31f930716" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffff00000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "8d63a269b14d506ccc401ab8a9f1b591" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffff80000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "d317f81dc6aa454aee4bd4a5a5cff4bd" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "19c80ec4a6deb7e5ed1033dda933498f" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "3cf5e1d21a17956d1dffad6a7c41c659" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "45899367c3132849763073c435a9288a766c8b9ec2308516" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "69fd12e8505f8ded2fdcb197a121b362" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "1b077a6af4b7f98229de786d7516b639" );
            unhexify( src_str, "275cfc0413d8ccb70513c3859b1d0f72" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "9c2d8842e5f48f57648205d39a239af1" );
            unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "bff52510095f518ecca60af4205444bb" );
            unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffff000000000000" );
            unhexify( src_str, "54d632d03aba0bd0f91877ebdd4d09cb" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffff800000000000" );
            unhexify( src_str, "d3427be7e4d27cd54f5fe37b03cf0897" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffffc00000000000" );
            unhexify( src_str, "b2099795e88cc158fd75ea133d7e7fbe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffe000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "bbd1097a62433f79449fa97d4ee80dbf" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffff000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "07058e408f5b99b0e0f061a1761b5b3b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffff800000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "5fd1f13fa0f31e37fabde328f894eac2" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "649a71545378c783e368c9ade7114f6c" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "47cb030da2ab051dfc6c4bf6910d12bb" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "798c7c005dee432b2c8ea5dfa381ecc3" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "0b24af36193ce4665f2825d7b4749c98" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "761c1fe41a18acf20d241650611d90f1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "8a560769d605868ad80d819bdba03771" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffffffffe0000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "2be1fae5048a25582a679ca10905eb80" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffff0000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "da86f292c6f41ea34fb2068df75ecc29" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffff8000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "220df19f85d69b1b562fa69a3c5beca5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffff800000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "be66cfea2fecd6bf0ec7b4352c99bcaa" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffc00000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "df31144f87a2ef523facdcf21a427804" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffe00000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "b5bb0f5629fb6aae5e1839a3c3625d63" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "531c2c38344578b84d50b3c917bbb6e1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fc6aec906323480005c58e7e1ab004ad" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "a3944b95ca0b52043584ef02151926a8" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "761c1fe41a18acf20d241650611d90f1" );
            unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "8a560769d605868ad80d819bdba03771" );
            unhexify( src_str, "38f2c7ae10612415d27ca190d27da8b4" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "91fbef2d15a97816060bee1feaa49afe" );
            unhexify( src_str, "1bc704f1bce135ceb810341b216d7abe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "e0000000000000000000000000000000" );
            unhexify( src_str, "9b80eefb7ebe2d2b16247aa0efc72f5d" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "f0000000000000000000000000000000" );
            unhexify( src_str, "7f2c5ece07a98d8bee13c51177395ff7" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "f8000000000000000000000000000000" );
            unhexify( src_str, "7818d800dcf6f4be1e0e94f403d1e4c2" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_AES_C */

}
FCT_END();

