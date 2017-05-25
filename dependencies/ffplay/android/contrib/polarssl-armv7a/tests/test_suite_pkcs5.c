#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/pkcs5.h>

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
#ifdef POLARSSL_PKCS5_C


    FCT_SUITE_BGN(test_suite_pkcs5)
    {

        FCT_TEST_BGN(pbkdf2_rfc_6070_test_vector_1_sha1)
        {
            unsigned char pw_str[100];
            unsigned char salt_str[100];
            unsigned char dst_str[100];
        
            md_context_t ctx;
            const md_info_t *info;
        
            int pw_len, salt_len;
            unsigned char key[100];
        
            memset(pw_str, 0x00, 100);
            memset(salt_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
        
            pw_len = unhexify( pw_str, "70617373776f7264" );
            salt_len = unhexify( salt_str, "73616c74" );
        
        
            info = md_info_from_type( POLARSSL_MD_SHA1 );
            fct_chk( info != NULL );
            fct_chk( md_init_ctx( &ctx, info ) == 0 );
            fct_chk( pkcs5_pbkdf2_hmac( &ctx, pw_str, pw_len, salt_str, salt_len,
                                             1, 20, key ) == 0 );
        
            hexify( dst_str, key, 20 );
            fct_chk( strcmp( (char *) dst_str, "0c60c80f961f0e71f3a9b524af6012062fe037a6" ) == 0 );
        
            md_free_ctx( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(pbkdf2_rfc_6070_test_vector_2_sha1)
        {
            unsigned char pw_str[100];
            unsigned char salt_str[100];
            unsigned char dst_str[100];
        
            md_context_t ctx;
            const md_info_t *info;
        
            int pw_len, salt_len;
            unsigned char key[100];
        
            memset(pw_str, 0x00, 100);
            memset(salt_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
        
            pw_len = unhexify( pw_str, "70617373776f7264" );
            salt_len = unhexify( salt_str, "73616c74" );
        
        
            info = md_info_from_type( POLARSSL_MD_SHA1 );
            fct_chk( info != NULL );
            fct_chk( md_init_ctx( &ctx, info ) == 0 );
            fct_chk( pkcs5_pbkdf2_hmac( &ctx, pw_str, pw_len, salt_str, salt_len,
                                             2, 20, key ) == 0 );
        
            hexify( dst_str, key, 20 );
            fct_chk( strcmp( (char *) dst_str, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" ) == 0 );
        
            md_free_ctx( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(pbkdf2_rfc_6070_test_vector_3_sha1)
        {
            unsigned char pw_str[100];
            unsigned char salt_str[100];
            unsigned char dst_str[100];
        
            md_context_t ctx;
            const md_info_t *info;
        
            int pw_len, salt_len;
            unsigned char key[100];
        
            memset(pw_str, 0x00, 100);
            memset(salt_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
        
            pw_len = unhexify( pw_str, "70617373776f7264" );
            salt_len = unhexify( salt_str, "73616c74" );
        
        
            info = md_info_from_type( POLARSSL_MD_SHA1 );
            fct_chk( info != NULL );
            fct_chk( md_init_ctx( &ctx, info ) == 0 );
            fct_chk( pkcs5_pbkdf2_hmac( &ctx, pw_str, pw_len, salt_str, salt_len,
                                             4096, 20, key ) == 0 );
        
            hexify( dst_str, key, 20 );
            fct_chk( strcmp( (char *) dst_str, "4b007901b765489abead49d926f721d065a429c1" ) == 0 );
        
            md_free_ctx( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(pbkdf2_rfc_6070_test_vector_5_sha1)
        {
            unsigned char pw_str[100];
            unsigned char salt_str[100];
            unsigned char dst_str[100];
        
            md_context_t ctx;
            const md_info_t *info;
        
            int pw_len, salt_len;
            unsigned char key[100];
        
            memset(pw_str, 0x00, 100);
            memset(salt_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
        
            pw_len = unhexify( pw_str, "70617373776f726450415353574f524470617373776f7264" );
            salt_len = unhexify( salt_str, "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74" );
        
        
            info = md_info_from_type( POLARSSL_MD_SHA1 );
            fct_chk( info != NULL );
            fct_chk( md_init_ctx( &ctx, info ) == 0 );
            fct_chk( pkcs5_pbkdf2_hmac( &ctx, pw_str, pw_len, salt_str, salt_len,
                                             4096, 25, key ) == 0 );
        
            hexify( dst_str, key, 25 );
            fct_chk( strcmp( (char *) dst_str, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038" ) == 0 );
        
            md_free_ctx( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(pbkdf2_rfc_6070_test_vector_6_sha1)
        {
            unsigned char pw_str[100];
            unsigned char salt_str[100];
            unsigned char dst_str[100];
        
            md_context_t ctx;
            const md_info_t *info;
        
            int pw_len, salt_len;
            unsigned char key[100];
        
            memset(pw_str, 0x00, 100);
            memset(salt_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
        
            pw_len = unhexify( pw_str, "7061737300776f7264" );
            salt_len = unhexify( salt_str, "7361006c74" );
        
        
            info = md_info_from_type( POLARSSL_MD_SHA1 );
            fct_chk( info != NULL );
            fct_chk( md_init_ctx( &ctx, info ) == 0 );
            fct_chk( pkcs5_pbkdf2_hmac( &ctx, pw_str, pw_len, salt_str, salt_len,
                                             4096, 16, key ) == 0 );
        
            hexify( dst_str, key, 16 );
            fct_chk( strcmp( (char *) dst_str, "56fa6aa75548099dcc37d7f03425e0c3" ) == 0 );
        
            md_free_ctx( &ctx );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_PKCS5_C */

}
FCT_END();

