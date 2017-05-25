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

        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff8000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "8b527a6aebdaec9eaef8eda2cb7783e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffc000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "43fdaf53ebbc9880c228617d6a9b548b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffe000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "53786104b9744b98f052c46f1c850d0b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e37b1c6aa2846f6fdb413f238b089f23" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "43c9f7e62f5d288bb27aa40ef8fe1ea8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "6c002b682483e0cabcc731c253be5674" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3580d19cff44f1014a7c966a69059de5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "143ae8ed6555aba96110ab58893a8ae1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "806da864dd29d48deafbe764f8202aef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "6a118a874519e64e9963798a503f1d35" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "dc43be40be0e53712f7e2bf5ca707209" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "cb9fceec81286ca3e989bd979b0cb284" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "92beedab1895a94faa69b632e5cc47ce" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "b26aeb1874e47ca8358ff22378f09144" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "459264f4798f6a78bacb89c15ed3d601" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffffffffffc000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "90684a2ac55fe1ec2b8ebd5622520b73" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffffffffffe000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "7472f9a7988607ca79707795991035e6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fffffffffffffffffffffff000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "56aff089878bf3352f8df172a3ae47d8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffe00000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "23f710842b9bb9c32f26648c786807ca" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffff00000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "44a98bf11e163f632c47ec6a49683a89" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffff80000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "0f18aff94274696d9b61848bd50ac5e5" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e234cdca2606b81f29408d5f6da21206" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fff60a4740086b3b9c56195b98d91a7b" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "13237c49074a3da078dc1d828bb78c6f" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8146a08e2357f0caa30ca8c94d1a0544" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3071a2a48fe6cbd04f1a129098e308f8" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4b98e06d356deb07ebb824e5713f7be3" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "0336763e966d92595a567cc9ce537f5e" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "f34481ec3cc627bacd5dc3fb08f273e6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "a9a1631bf4996954ebc093957b234589" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "9798c4640bad75c7c3227db910174e72" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ff4f8391a6a40ca5b25d23bedd44a597" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "96ab5c2ff612d9dfaae8c31f30c42168" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "f9b0fda0c4a898f5b9e6f661c4ce4d07" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffff0" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8ade895913685c67c5269f8aae42983e" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffff8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "39bde67d5c8ed8a8b1c37eb8fa9f5ac0" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffffc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffe00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ddb505e6cc1384cbaec1df90b80beb20" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffff00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "5674a3bed27bf4bd3622f9f5fe208306" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffff80" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "b687f26a89cfbfbb8e5eeac54055315e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3608c344868e94555d23a120f8a5502d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "77da2021935b840b7f5dcc39132da9e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3b7c24f825e3bf9873c9f14d39a0e6f4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "51719783d3185a535bd75adc65071ce1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "26aa49dcfe7629a8901a69a9914e6dfd" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "d5e08bf9a182e857cf40b3a36ee248cc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "941a4773058224e1ef66d10e0a6ee782" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "067cd9d3749207791841562507fa9626" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffc00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "030d7e5b64f380a7e4ea5387b5cd7f49" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffe00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0dc9a2610037009b698f11bb7e86c83e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fff00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0046612c766d1840c226364f1fa7ed72" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "902d88d13eae52089abd6143cfe394e9" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffe00000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "d49bceb3b823fedd602c305345734bd2" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffff00000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "707b1dbb0ffa40ef7d95def421233fae" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffff80000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffc0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8dfd999be5d0cfa35732c0ddc88ff5a5" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffe0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "02647c76a300c3173b841487eb2bae9f" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffff0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "172df8b02f04b53adab028b4e01acd87" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "3cf5e1d21a17956d1dffad6a7c41c659" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "45899367c3132849763073c435a9288a766c8b9ec2308516" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "69fd12e8505f8ded2fdcb197a121b362" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8aa584e2cc4d17417a97cb9a28ba29c8" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "9c2d8842e5f48f57648205d39a239af1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "bff52510095f518ecca60af4205444bb" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4f354592ff7c8847d2d0870ca9481b7c" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "51719783d3185a535bd75adc65071ce1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "e35a6dcb19b201a01ebcfa8aa22b5759" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "b29169cdcf2d83e838125a12ee6aa400" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "d8f3a72fc3cdf74dfaf6c3e6b97b2fa6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fc6aec906323480005c58e7e1ab004ad" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "a3944b95ca0b52043584ef02151926a8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "a74289fe73a4c123ca189ea1e1b49ad5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "761c1fe41a18acf20d241650611d90f1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8a560769d605868ad80d819bdba03771" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "91fbef2d15a97816060bee1feaa49afe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "1bc704f1bce135ceb810341b216d7abe" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffff800000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0d9ac756eb297695eed4d382eb126d26" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffc00000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "56ede9dda3f6f141bff1757fa689c3e1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffe00000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "768f520efe0f23e61d3ec8ad9ce91774" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "49af6b372135acef10132e548f217b17" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ff000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8bcd40f94ebb63b9f7909676e667f1e7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ff800000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fe1cffb83f45dcfb38b29be438dbd3ab" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ffc00000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "cca7c3086f5f9511b31233da7cab9160" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "5b40ff4ec9be536ba23035fa4f06064c" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "60eb5af8416b257149372194e8b88749" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "798c7c005dee432b2c8ea5dfa381ecc3" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "637c31dc2591a07636f646b72daabbe7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "179a49c712154bbffbe6e7a84a18e220" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "5c9d844ed46f9885085e5d6a4f94c7d7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "014730f80ac625fe84f026c60bfd547d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0b24af36193ce4665f2825d7b4749c98" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "761c1fe41a18acf20d241650611d90f1" ) == 0 );
            }
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_AES_C */

}
FCT_END();

