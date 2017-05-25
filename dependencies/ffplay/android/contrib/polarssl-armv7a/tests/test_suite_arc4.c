#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/arc4.h>

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
#ifdef POLARSSL_ARC4_C


    FCT_SUITE_BGN(test_suite_arc4)
    {

        FCT_TEST_BGN(test_vector_arc4_cryptlib)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[1000];
            unsigned char dst_hexstr[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            memset(dst_hexstr, 0x00, 2000);
        
            src_len = unhexify( src_str, "0000000000000000" );
            key_len = unhexify( key_str, "0123456789abcdef" );
        
            arc4_setup(&ctx, key_str, key_len);
            fct_chk( arc4_crypt(&ctx, src_len, src_str, dst_str ) == 0 );
            hexify( dst_hexstr, dst_str, src_len );
        
            fct_chk( strcmp( (char *) dst_hexstr, "7494c2e7104b0879" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_vector_arc4_commerce)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[1000];
            unsigned char dst_hexstr[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            memset(dst_hexstr, 0x00, 2000);
        
            src_len = unhexify( src_str, "dcee4cf92c" );
            key_len = unhexify( key_str, "618a63d2fb" );
        
            arc4_setup(&ctx, key_str, key_len);
            fct_chk( arc4_crypt(&ctx, src_len, src_str, dst_str ) == 0 );
            hexify( dst_hexstr, dst_str, src_len );
        
            fct_chk( strcmp( (char *) dst_hexstr, "f13829c9de" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_vector_arc4_ssh_arcfour)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[1000];
            unsigned char dst_hexstr[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            memset(dst_hexstr, 0x00, 2000);
        
            src_len = unhexify( src_str, "527569736c696e6e756e206c61756c75206b6f727669737373616e692c2074e4686be470e46964656e2070e4e46c6ce42074e47973696b75752e204b6573e479f66e206f6e206f6e6e69206f6d616e616e692c206b61736b6973617675756e206c61616b736f7420766572686f75752e20456e206d6120696c6f697473652c20737572652068756f6b61612c206d75747461206d657473e46e2074756d6d757573206d756c6c652074756f6b61612e205075756e746f2070696c76656e2c206d692068756b6b75752c207369696e746f20766172616e207475756c6973656e2c206d69206e756b6b75752e2054756f6b7375742076616e616d6f6e206a61207661726a6f74207665656e2c206e69697374e420737964e46d656e69206c61756c756e207465656e2e202d2045696e6f204c65696e6f" );
            key_len = unhexify( key_str, "29041972fb42ba5fc7127712f13829c9" );
        
            arc4_setup(&ctx, key_str, key_len);
            fct_chk( arc4_crypt(&ctx, src_len, src_str, dst_str ) == 0 );
            hexify( dst_hexstr, dst_str, src_len );
        
            fct_chk( strcmp( (char *) dst_hexstr, "358186999001e6b5daf05eceeb7eee21e0689c1f00eea81f7dd2caaee1d2763e68af0ead33d66c268bc946c484fbe94c5f5e0b86a59279e4f824e7a640bd223210b0a61160b7bce986ea65688003596b630a6b90f8e0caf6912a98eb872176e83c202caa64166d2cce57ff1bca57b213f0ed1aa72fb8ea52b0be01cd1e412867720b326eb389d011bd70d8af035fb0d8589dbce3c666f5ea8d4c7954c50c3f340b0467f81b425961c11843074df620f208404b394cf9d37ff54b5f1ad8f6ea7da3c561dfa7281f964463d2cc35a4d1b03490dec51b0711fbd6f55f79234d5b7c766622a66de92be996461d5e4dc878ef9bca030521e8351e4baed2fd04f9467368c4ad6ac186d08245b263a2666d1f6c5420f1599dfd9f438921c2f5a463938ce0982265eef70179bc553f339eb1a4c1af5f6a547f" ) == 0 );
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(arc4_selftest)
        {
            fct_chk( arc4_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_ARC4_C */

}
FCT_END();

