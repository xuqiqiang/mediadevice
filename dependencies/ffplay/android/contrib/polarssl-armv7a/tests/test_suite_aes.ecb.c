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

        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "0336763e966d92595a567cc9ce537f5e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "9798c4640bad75c7c3227db910174e72" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "a9a1631bf4996954ebc093957b234589" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "96ab5c2ff612d9dfaae8c31f30c42168" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff4f8391a6a40ca5b25d23bedd44a597" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e0000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "72a1da770f5d7ac4c9ef94d822affd97" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "970014d634e2b7650777e8e84d03ccd8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "f17e79aed0db7e279e955b5f493875a7" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff0000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "7b90785125505fad59b13c186dd66ce3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff8000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8b527a6aebdaec9eaef8eda2cb7783e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffc000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "43fdaf53ebbc9880c228617d6a9b548b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffc000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "70c46bb30692be657f7eaa93ebad9897" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffe000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "323994cfb9da285a5d9642e1759b224a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffff000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1dbf57877b7b17385c85d0b54851e371" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffc00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "3a4d354f02bb5a5e47d39666867f246a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffe00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d451b8d6e1e1a0ebb155fbbf6e7b7dc3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffff00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "6898d4f42fa7ba6a10ac05e87b9f2080" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffffffffffffe0000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "082eb8be35f442fb52668e16a591d1d6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffffff0000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "e656f9ecf5fe27ec3e4a73d00c282fb3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffffff8000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "2ca8209d63274cd9a29bb74bcd77683a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "db4f1aa530967d6732ce4715eb0ee24b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "a81738252621dd180a34f3455b4baa2f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff800000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "77e2b508db7fd89234caf7939ee5621a" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffc00000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "dc43be40be0e53712f7e2bf5ca707209" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "6a118a874519e64e9963798a503f1d35" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "92beedab1895a94faa69b632e5cc47ce" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "cb9fceec81286ca3e989bd979b0cb284" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "459264f4798f6a78bacb89c15ed3d601" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "b26aeb1874e47ca8358ff22378f09144" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b69418a85332240dc82492353956ae0c" );
            unhexify( src_str, "a303d940ded8f0baff6f75414cac5243" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "71b5c08a1993e1362e4d0ce9b22b78d5" );
            unhexify( src_str, "c2dabd117f8a3ecabfbb11d12194d9d0" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e234cdca2606b81f29408d5f6da21206" );
            unhexify( src_str, "fff60a4740086b3b9c56195b98d91a7b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff0000000000000000" );
            unhexify( src_str, "84be19e053635f09f2665e7bae85b42d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff8000000000000000" );
            unhexify( src_str, "32cd652842926aea4aa6137bb2be2b5e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffff80000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "156f07767a85a4312321f63968338a01" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffc0000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "15eec9ebf42b9ca76897d2cd6c5a12e2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffe0000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "db0d3a6fdcc13f915e2b302ceeb70fd8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "51719783d3185a535bd75adc65071ce1" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "26aa49dcfe7629a8901a69a9914e6dfd" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d5e08bf9a182e857cf40b3a36ee248cc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "941a4773058224e1ef66d10e0a6ee782" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "067cd9d3749207791841562507fa9626" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "dd619e1cf204446112e0af2b9afa8f8c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d4f0aae13c8fe9339fbf9e69ed0ad74d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "19c80ec4a6deb7e5ed1033dda933498f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffff800000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8dd274bd0f1b58ae345d9e7233f9b8f3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffc00000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "9d6bdc8f4ce5feb0f3bed2e4b9a9bb0b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffe00000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "fd5548bcf3f42565f7efa94562528d46" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffff000000000000000" );
            unhexify( src_str, "bb2852c891c5947d2ed44032c421b85f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffff800000000000000" );
            unhexify( src_str, "1b9f5fbd5e8a4264c0a85b80409afa5e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffc00000000000000" );
            unhexify( src_str, "30dab809f85a917fe924733f424ac589" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79" );
            unhexify( src_str, "cfe4d74002696ccf7d87b14a2f9cafc9" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570" );
            unhexify( src_str, "d2eafd86f63b109b91f5dbb3a3fb7e13" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6" );
            unhexify( src_str, "9b9fdd1c5975655f539998b306a324af" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "275cfc0413d8ccb70513c3859b1d0f72" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1b077a6af4b7f98229de786d7516b639" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "9c2d8842e5f48f57648205d39a239af1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "bff52510095f518ecca60af4205444bb" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "b2099795e88cc158fd75ea133d7e7fbe" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffffffffc00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "a6cae46fb6fadfe7a2c302a34242817b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffffffffe00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "026a7024d6a902e0b3ffccbaa910cc3f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffff00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "352065272169abf9856843927d0674fd" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4307456a9e67813b452e15fa8fffe398" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4663446607354989477a5c6f0f007ef4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "0b24af36193ce4665f2825d7b4749c98" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "761c1fe41a18acf20d241650611d90f1" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "8a560769d605868ad80d819bdba03771" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffff80000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "36aff0ef7bf3280772cf4cac80a0d2b2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffffc0000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1f8eedea0f62a1406d58cfc3ecea72cf" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffffe0000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "abf4154a3375a1d3e6b1d454438f95a6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffff8000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "45d089c36d5c5a4efc689e3b0de10dd5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffc000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "b4da5df4becb5462e03a0ed00d295629" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffe000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "dcf4e129136c1a4b7a0f38935cc34b2b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000" );
            unhexify( src_str, "edf61ae362e882ddc0167474a7a77f3a" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000" );
            unhexify( src_str, "6168b00ba7859e0970ecfd757efecf7c" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000" );
            unhexify( src_str, "d1415447866230d28bb1ea18a4cdfd02" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( src_str, "a3944b95ca0b52043584ef02151926a8" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e" );
            unhexify( src_str, "a74289fe73a4c123ca189ea1e1b49ad5" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707" );
            unhexify( src_str, "b91d4ea4488644b56cf0812fa7fcf5fc" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "761c1fe41a18acf20d241650611d90f1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "38f2c7ae10612415d27ca190d27da8b4" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8a560769d605868ad80d819bdba03771" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "1bc704f1bce135ceb810341b216d7abe" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "91fbef2d15a97816060bee1feaa49afe" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ddc6bf790c15760d8d9aeb6f9a75fd4e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "80000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "0a6bdc6d4c1e6280301fd8e97ddbe601" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "c0000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "9b80eefb7ebe2d2b16247aa0efc72f5d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "e0000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_AES_C */

}
FCT_END();

