#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/cipher.h>

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
#ifdef POLARSSL_CIPHER_C


    FCT_SUITE_BGN(test_suite_cipher)
    {
#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(cipher_selftest)
        {
            fct_chk( cipher_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */


        FCT_TEST_BGN(decrypt_empty_buffer)
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            const cipher_info_t *cipher_info;
        
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
        
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
        
            /* decode 0-byte string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, 0, decbuf, &outlen ) );
            fct_chk( 0 == outlen );
            fct_chk( POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            fct_chk( 0 == outlen );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
        FCT_TEST_END();

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes)
            size_t length = 0;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_byte)
            size_t length = 1;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_2_bytes)
            size_t length = 2;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_7_bytes)
            size_t length = 7;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_8_bytes)
            size_t length = 8;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_9_bytes)
            size_t length = 9;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_15_bytes)
            size_t length = 15;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes)
            size_t length = 16;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_17_bytes)
            size_t length = 17;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_31_bytes)
            size_t length = 31;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 32;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 33;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_47_bytes)
            size_t length = 47;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_48_bytes)
            size_t length = 48;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_49_bytes)
            size_t length = 49;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes_in_multiple_parts)
            size_t first_length = 0;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_1)
            size_t first_length = 1;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_3)
            size_t first_length = 1;
            size_t second_length = 15;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_4)
            size_t first_length = 15;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 15;
            size_t second_length = 7;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 17;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes)
            size_t length = 0;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_byte)
            size_t length = 1;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_2_bytes)
            size_t length = 2;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_7_bytes)
            size_t length = 7;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_8_bytes)
            size_t length = 8;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_9_bytes)
            size_t length = 9;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_15_bytes)
            size_t length = 15;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes)
            size_t length = 16;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_17_bytes)
            size_t length = 17;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_31_bytes)
            size_t length = 31;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 32;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 33;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_47_bytes)
            size_t length = 47;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_48_bytes)
            size_t length = 48;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_49_bytes)
            size_t length = 49;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CFB128" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes_in_multiple_parts)
            size_t first_length = 0;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_1)
            size_t first_length = 1;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_3)
            size_t first_length = 1;
            size_t second_length = 15;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_4)
            size_t first_length = 15;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 15;
            size_t second_length = 7;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 17;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CFB128 );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes)
            size_t length = 0;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_byte)
            size_t length = 1;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_2_bytes)
            size_t length = 2;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_7_bytes)
            size_t length = 7;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_8_bytes)
            size_t length = 8;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_9_bytes)
            size_t length = 9;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_15_bytes)
            size_t length = 15;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes)
            size_t length = 16;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_17_bytes)
            size_t length = 17;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_31_bytes)
            size_t length = 31;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 32;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 33;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_47_bytes)
            size_t length = 47;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_48_bytes)
            size_t length = 48;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_49_bytes)
            size_t length = 49;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-128-CTR" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes_in_multiple_parts)
            size_t first_length = 0;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_1)
            size_t first_length = 1;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_3)
            size_t first_length = 1;
            size_t second_length = 15;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_4)
            size_t first_length = 15;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 15;
            size_t second_length = 7;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 17;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C
#ifdef POLARSSL_CIPHER_MODE_CTR

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_CIPHER_MODE_CTR */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes)
            size_t length = 0;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_byte)
            size_t length = 1;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_2_bytes)
            size_t length = 2;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_7_bytes)
            size_t length = 7;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_8_bytes)
            size_t length = 8;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_9_bytes)
            size_t length = 9;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_15_bytes)
            size_t length = 15;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes)
            size_t length = 16;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_17_bytes)
            size_t length = 17;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_31_bytes)
            size_t length = 31;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 32;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 33;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_47_bytes)
            size_t length = 47;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_48_bytes)
            size_t length = 48;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_49_bytes)
            size_t length = 49;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-192-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes_in_multiple_parts)
            size_t first_length = 0;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_1)
            size_t first_length = 1;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_3)
            size_t first_length = 1;
            size_t second_length = 15;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_4)
            size_t first_length = 15;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 15;
            size_t second_length = 7;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 17;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 192, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 192, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes)
            size_t length = 0;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_byte)
            size_t length = 1;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_2_bytes)
            size_t length = 2;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_7_bytes)
            size_t length = 7;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_8_bytes)
            size_t length = 8;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_9_bytes)
            size_t length = 9;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_15_bytes)
            size_t length = 15;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes)
            size_t length = 16;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_17_bytes)
            size_t length = 17;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_31_bytes)
            size_t length = 31;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 32;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes)
            size_t length = 33;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_47_bytes)
            size_t length = 47;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_48_bytes)
            size_t length = 48;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_49_bytes)
            size_t length = 49;
            unsigned char key[32];
            unsigned char iv[16];
        
            const cipher_info_t *cipher_info;
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
            
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Check and get info structures */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info );
            fct_chk( cipher_info_from_string( "AES-256-CBC" ) == cipher_info );
        
            /* Initialise enc and dec contexts */
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size( &ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == enclen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
        
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_0_bytes_in_multiple_parts)
            size_t first_length = 0;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_1)
            size_t first_length = 1;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_1_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 0;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_2)
            size_t first_length = 0;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_3)
            size_t first_length = 1;
            size_t second_length = 15;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_16_bytes_in_multiple_parts_4)
            size_t first_length = 15;
            size_t second_length = 1;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 15;
            size_t second_length = 7;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_22_bytes_in_multiple_parts_1)
            size_t first_length = 17;
            size_t second_length = 6;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

#ifdef POLARSSL_AES_C

        FCT_TEST_BGN(aes_encrypt_and_decrypt_32_bytes_in_multiple_parts_1)
            size_t first_length = 16;
            size_t second_length = 16;
            size_t length = first_length + second_length;
            unsigned char key[32];
            unsigned char iv[16];
        
            cipher_context_t ctx_dec;
            cipher_context_t ctx_enc;
            const cipher_info_t *cipher_info;
        
            unsigned char inbuf[64];
            unsigned char encbuf[64];
            unsigned char decbuf[64];
        
            size_t outlen = 0;
            size_t totaloutlen = 0;
            size_t enclen = 0;
        
            memset( key, 0, 32 );
            memset( iv , 0, 16 );
            
            memset( &ctx_dec, 0, sizeof( ctx_dec ) );
            memset( &ctx_enc, 0, sizeof( ctx_enc ) );
                
            memset( inbuf, 5, 64 );
            memset( encbuf, 0, 64 );
            memset( decbuf, 0, 64 );
        
            /* Initialise enc and dec contexts */
            cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
            fct_chk( NULL != cipher_info);
            
            fct_chk( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
            fct_chk( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
            
            fct_chk( 0 == cipher_setkey( &ctx_dec, key, 256, POLARSSL_DECRYPT ) );
            fct_chk( 0 == cipher_setkey( &ctx_enc, key, 256, POLARSSL_ENCRYPT ) );
        
            fct_chk( 0 == cipher_reset( &ctx_dec, iv ) );
            fct_chk( 0 == cipher_reset( &ctx_enc, iv ) );
        
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                enclen = cipher_get_block_size(&ctx_enc )
                            * ( 1 + length / cipher_get_block_size( &ctx_enc ) );
            }
            else
            {
                enclen = length;
            }
        
            /* encode length number of bytes from inbuf */
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
            totaloutlen = outlen;
            fct_chk( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( totaloutlen == enclen - cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( totaloutlen == enclen );
            }
            fct_chk( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
            totaloutlen += outlen;
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( outlen == cipher_get_block_size ( &ctx_enc ) );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
        
            /* decode the previously encoded string */
            fct_chk( 0 == cipher_update( &ctx_dec, encbuf, enclen, decbuf, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( enclen - cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( enclen == outlen );
            }
            fct_chk( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
            if( POLARSSL_MODE_CBC == cipher_info->mode )
            {
                fct_chk( length - enclen + cipher_get_block_size ( &ctx_enc ) == outlen );
            }
            else
            {
                fct_chk( outlen == 0 );
            }
            
        
            fct_chk( 0 == memcmp(inbuf, decbuf, length) );
        
            fct_chk( 0 == cipher_free_ctx( &ctx_dec ) );
            fct_chk( 0 == cipher_free_ctx( &ctx_enc ) );
        FCT_TEST_END();
#endif /* POLARSSL_AES_C */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_CIPHER_C */

}
FCT_END();

