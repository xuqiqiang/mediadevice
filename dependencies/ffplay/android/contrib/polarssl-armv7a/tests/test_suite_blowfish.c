#include "fct.h"
#include <polarssl/config.h>

#include "polarssl/blowfish.h"

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
#ifdef POLARSSL_BLOWFISH_C


    FCT_SUITE_BGN(test_suite_blowfish)
    {

        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "0000000000000000" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "4ef997456198dd78" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff" );
            unhexify( src_str, "ffffffffffffffff" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "51866fd5b85ecb8a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3000000000000000" );
            unhexify( src_str, "1000000000000001" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "7d856f9a613063f2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "1111111111111111" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "2466dd878b963c9d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdef" );
            unhexify( src_str, "1111111111111111" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "61f9c3802281b096" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "0123456789abcdef" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "7d0cc630afda1ec7" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "0000000000000000" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "4ef997456198dd78" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fedcba9876543210" );
            unhexify( src_str, "0123456789abcdef" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0aceab0fc6a0a28d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "7ca110454a1a6e57" );
            unhexify( src_str, "01a1d6d039776742" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "59c68245eb05282b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0131d9619dc1376e" );
            unhexify( src_str, "5cd54ca83def57da" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "b1b8cc0b250f09a0" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07a1133e4a0b2686" );
            unhexify( src_str, "0248d43806f67172" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1730e5778bea1da4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3849674c2602319e" );
            unhexify( src_str, "51454b582ddf440a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "a25e7856cf2651eb" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "04b915ba43feb5b6" );
            unhexify( src_str, "42fd443059577fa2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "353882b109ce8f1a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0113b970fd34f2ce" );
            unhexify( src_str, "059b5e0851cf143a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "48f4d0884c379918" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0170f175468fb5e6" );
            unhexify( src_str, "0756d8e0774761d2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "432193b78951fc98" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "43297fad38e373fe" );
            unhexify( src_str, "762514b829bf486a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "13f04154d69d1ae5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07a7137045da2a16" );
            unhexify( src_str, "3bdd119049372802" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "2eedda93ffd39c79" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "04689104c2fd3b2f" );
            unhexify( src_str, "26955f6835af609a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "d887e0393c2da6e3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_19)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "37d06bb516cb7546" );
            unhexify( src_str, "164d5e404f275232" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "5f99d04f5b163969" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_20)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1f08260d1ac2465e" );
            unhexify( src_str, "6b056e18759f5cca" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "4a057a3b24d3977b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_21)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "584023641aba6176" );
            unhexify( src_str, "004bd6ef09176062" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "452031c1e4fada8e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_22)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "025816164629b007" );
            unhexify( src_str, "480d39006ee762f2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "7555ae39f59b87bd" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_23)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "49793ebc79b3258f" );
            unhexify( src_str, "437540c8698f3cfa" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "53c55f9cb49fc019" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_24)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "4fb05e1515ab73a7" );
            unhexify( src_str, "072d43a077075292" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "7a8e7bfa937e89a3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_25)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "49e95d6d4ca229bf" );
            unhexify( src_str, "02fe55778117f12a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "cf9c5d7a4986adb5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_26)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "018310dc409b26d6" );
            unhexify( src_str, "1d9d5c5018f728c2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "d1abb290658bc778" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_27)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1c587f1c13924fef" );
            unhexify( src_str, "305532286d6f295a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "55cb3774d13ef201" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_28)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0101010101010101" );
            unhexify( src_str, "0123456789abcdef" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "fa34ec4847b268b2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_29)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1f1f1f1f0e0e0e0e" );
            unhexify( src_str, "0123456789abcdef" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "a790795108ea3cae" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_30)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e0fee0fef1fef1fe" );
            unhexify( src_str, "0123456789abcdef" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "c39e072d9fac631d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_31)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "ffffffffffffffff" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "014933e0cdaff6e4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_32)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff" );
            unhexify( src_str, "0000000000000000" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "f21e9a77b71c49bc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_33)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdef" );
            unhexify( src_str, "0000000000000000" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "245946885754369a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_34)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fedcba9876543210" );
            unhexify( src_str, "ffffffffffffffff" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "6b5c5a9c5d9e0a5a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "4ef997456198dd78" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff" );
            unhexify( src_str, "51866fd5b85ecb8a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffff" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3000000000000000" );
            unhexify( src_str, "7d856f9a613063f2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1000000000000001" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "2466dd878b963c9d" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1111111111111111" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdef" );
            unhexify( src_str, "61f9c3802281b096" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1111111111111111" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "7d0cc630afda1ec7" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0123456789abcdef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "4ef997456198dd78" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fedcba9876543210" );
            unhexify( src_str, "0aceab0fc6a0a28d" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0123456789abcdef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "7ca110454a1a6e57" );
            unhexify( src_str, "59c68245eb05282b" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "01a1d6d039776742" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0131d9619dc1376e" );
            unhexify( src_str, "b1b8cc0b250f09a0" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "5cd54ca83def57da" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07a1133e4a0b2686" );
            unhexify( src_str, "1730e5778bea1da4" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0248d43806f67172" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3849674c2602319e" );
            unhexify( src_str, "a25e7856cf2651eb" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "51454b582ddf440a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "04b915ba43feb5b6" );
            unhexify( src_str, "353882b109ce8f1a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "42fd443059577fa2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0113b970fd34f2ce" );
            unhexify( src_str, "48f4d0884c379918" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "059b5e0851cf143a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_encrypt_ssleay_reference_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0170f175468fb5e6" );
            unhexify( src_str, "0756d8e0774761d2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "432193b78951fc98" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "43297fad38e373fe" );
            unhexify( src_str, "13f04154d69d1ae5" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "762514b829bf486a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07a7137045da2a16" );
            unhexify( src_str, "2eedda93ffd39c79" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "3bdd119049372802" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "04689104c2fd3b2f" );
            unhexify( src_str, "d887e0393c2da6e3" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "26955f6835af609a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_19)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "37d06bb516cb7546" );
            unhexify( src_str, "5f99d04f5b163969" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "164d5e404f275232" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_20)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1f08260d1ac2465e" );
            unhexify( src_str, "4a057a3b24d3977b" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "6b056e18759f5cca" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_21)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "584023641aba6176" );
            unhexify( src_str, "452031c1e4fada8e" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "004bd6ef09176062" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_22)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "025816164629b007" );
            unhexify( src_str, "7555ae39f59b87bd" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "480d39006ee762f2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_23)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "49793ebc79b3258f" );
            unhexify( src_str, "53c55f9cb49fc019" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "437540c8698f3cfa" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_24)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "4fb05e1515ab73a7" );
            unhexify( src_str, "7a8e7bfa937e89a3" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "072d43a077075292" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_25)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "49e95d6d4ca229bf" );
            unhexify( src_str, "cf9c5d7a4986adb5" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "02fe55778117f12a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_26)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "018310dc409b26d6" );
            unhexify( src_str, "d1abb290658bc778" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1d9d5c5018f728c2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_27)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1c587f1c13924fef" );
            unhexify( src_str, "55cb3774d13ef201" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "305532286d6f295a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_28)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0101010101010101" );
            unhexify( src_str, "fa34ec4847b268b2" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0123456789abcdef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_29)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1f1f1f1f0e0e0e0e" );
            unhexify( src_str, "a790795108ea3cae" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0123456789abcdef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_30)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e0fee0fef1fef1fe" );
            unhexify( src_str, "c39e072d9fac631d" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0123456789abcdef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_31)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "014933e0cdaff6e4" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffff" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_32)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff" );
            unhexify( src_str, "f21e9a77b71c49bc" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_33)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdef" );
            unhexify( src_str, "245946885754369a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "0000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ecb_decrypt_ssleay_reference_34)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fedcba9876543210" );
            unhexify( src_str, "6b5c5a9c5d9e0a5a" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffff" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "be1e639408640f05" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "b39e44481bdb1e6e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "9457aa83b1928c0d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a596" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "8bb77032f960629d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a59687" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "e87a244e2cc85e82" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "15750e7a4f4ec577" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a596877869" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "122ba70b3ab64ae0" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "3a833c9affc537f6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "9409da87a90f6bf2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "884f80625060b8b4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "1f85031c19e11968" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "79d9373a714ca34f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "93142887ee3be15c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "03429e838ce2d14b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f0011" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "a4299e27469ff67b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_19)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f001122" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "afd5aed1c1bc96a8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_20)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "10851c0e3858da9f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_21)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "e6f51ed79b9db21f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_22)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f001122334455" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "64a6e14afd36b46f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_23)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "80c7d7d45a5479ad" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_ssleay_reference_24)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344556677" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "05044b62fa52d080" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_440_bits)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff0123456789abcdef0102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "9a2ab8f1b00c73d2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_448_bits)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff0123456789abcdef0102030405060708090a0b0c0d0e0fff" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "2fb3ab7f0ee91b69" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_setkey_setkey_456_bits)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff0123456789abcdef0102030405060708090a0b0c0d0e0fffff" );
            unhexify( src_str, "fedcba9876543210" );
        
            fct_chk( blowfish_setkey( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( blowfish_crypt_ecb( &ctx, BLOWFISH_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 8 );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cbc_encrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            data_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520666F722000000000" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
        
            fct_chk( blowfish_crypt_cbc( &ctx, BLOWFISH_ENCRYPT, data_len , iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cbc_decrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            data_len = unhexify( src_str, "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_cbc( &ctx, BLOWFISH_DECRYPT, data_len , iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "37363534333231204e6f77206973207468652074696d6520666f722000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cbc_encrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            data_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520666F7220000000" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
        
            fct_chk( blowfish_crypt_cbc( &ctx, BLOWFISH_ENCRYPT, data_len , iv_str, src_str, output ) == POLARSSL_ERR_BLOWFISH_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_INPUT_LENGTH == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cbc_decrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            data_len = unhexify( src_str, "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC00" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_cbc( &ctx, BLOWFISH_DECRYPT, data_len , iv_str, src_str, output ) == POLARSSL_ERR_BLOWFISH_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_BLOWFISH_INVALID_INPUT_LENGTH == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cfb_encrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            size_t iv_offset = 0;
            int key_len, src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            src_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520666F722000" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_cfb64( &ctx, BLOWFISH_ENCRYPT, src_len, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "e73214a2822139caf26ecf6d2eb9e76e3da3de04d1517200519d57a6c3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_cfb_decrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            size_t iv_offset = 0;
            int key_len, src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            src_len = unhexify( src_str, "E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_cfb64( &ctx, BLOWFISH_DECRYPT, src_len, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "37363534333231204e6f77206973207468652074696d6520666f722000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ctr_encrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char stream_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            size_t iv_offset = 0;
            int key_len, src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(stream_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            src_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520666F722000" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_ctr( &ctx, src_len, &iv_offset, iv_str, stream_str, src_str, output ) == 0 );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "e73214a2822139ca60254740dd8c5b8acf5e9569c4affeb944b8fc020e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(blowfish_ctr_decrypt)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char stream_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            blowfish_context ctx;
            size_t iv_offset = 0;
            int key_len, src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(stream_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789ABCDEFF0E1D2C3B4A59687" );
            unhexify( iv_str, "FEDCBA9876543210" );
            src_len = unhexify( src_str, "e73214a2822139ca60254740dd8c5b8acf5e9569c4affeb944b8fc020e" );
        
            blowfish_setkey( &ctx, key_str, key_len * 8 );
            fct_chk( blowfish_crypt_ctr( &ctx, src_len, &iv_offset, iv_str, stream_str, src_str, output ) == 0 );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "37363534333231204e6f77206973207468652074696d6520666f722000" ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_BLOWFISH_C */

}
FCT_END();

