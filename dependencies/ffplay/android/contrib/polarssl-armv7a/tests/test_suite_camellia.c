#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/camellia.h>

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
#ifdef POLARSSL_CAMELLIA_C


    FCT_SUITE_BGN(test_suite_camellia)
    {

        FCT_TEST_BGN(camellia_128_ecb_encrypt_rfc3713_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdeffedcba9876543210" );
            unhexify( src_str, "0123456789abcdeffedcba9876543210" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "67673138549669730857065648eabe43" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_rfc3713_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdeffedcba98765432100011223344556677" );
            unhexify( src_str, "0123456789abcdeffedcba9876543210" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "b4993401b3e996f84ee5cee7d79b09b9" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_rfc3713_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff" );
            unhexify( src_str, "0123456789abcdeffedcba9876543210" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "9acc237dff16d76c20ef7c919e3a7509" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "00112233445566778899AABBCCDDEEFF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "77CF412067AF8270613529149919546F" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000102030405060708090A0B0C0D0E0F1011121314151617" );
            unhexify( src_str, "00112233445566778899AABBCCDDEEFF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "B22F3C36B72D31329EEE8ADDC2906C68" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" );
            unhexify( src_str, "00112233445566778899AABBCCDDEEFF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "2EDF1F3418D53B88841FC8985FB1ECF2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "432FC5DCD628115B7C388D770B270C96" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_ecb_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "0BE1F14023782A22E8384C5ABB7FAB2B" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_ecb_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "A0A1ABCD1893AB6FE0FE5B65DF5F8636" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_ecb_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "E61925E0D5DFAA9BB29F815B3076E51A" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "CCCC6C4E138B45848514D48D0D3439D3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "5713C62C14B2EC0F8393B6AFD6F5785A" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "B40ED2B60EB54D09D030CF511FEEF366" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_ecb_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "909DBD95799096748CB27357E73E1D26" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "BEFD219B112FA00098919CD101C9CCFA" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "C91D3A8F1AEA08A9386CF4B66C0169EA" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "A623D711DC5F25A51BB8A80D56397D28" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_ecb_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "7960109FB6DC42947FCFE59EA3C5EB6B" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_cbc_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            data_len = unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "1607CF494B36BBF00DAEB0B503C831AB" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_cbc_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "1607CF494B36BBF00DAEB0B503C831AB" );
            data_len = unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "A2F2CF671629EF7840C5A5DFB5074887" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_cbc_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "A2F2CF671629EF7840C5A5DFB5074887" );
            data_len = unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "0F06165008CF8B8B5A63586362543E54" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_128_cbc_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "36A84CDAFD5F9A85ADA0F0A993D6D577" );
            data_len = unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "74C64268CDB8B8FAF5B34E8AF3732980" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_cbc_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            data_len = unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "2A4830AB5AC4A1A2405955FD2195CF93" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_cbc_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "2A4830AB5AC4A1A2405955FD2195CF93" );
            data_len = unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "5D5A869BD14CE54264F892A6DD2EC3D5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_cbc_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "5D5A869BD14CE54264F892A6DD2EC3D5" );
            data_len = unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "37D359C3349836D884E310ADDF68C449" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_192_cbc_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "37D359C3349836D884E310ADDF68C449" );
            data_len = unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "01FAAA930B4AB9916E9668E1428C6B08" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            data_len = unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "E6CFA35FC02B134A4D2C0B6737AC3EDA" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "E6CFA35FC02B134A4D2C0B6737AC3EDA" );
            data_len = unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "36CBEB73BD504B4070B1B7DE2B21EB50" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "36CBEB73BD504B4070B1B7DE2B21EB50" );
            data_len = unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "E31A6055297D96CA3330CDF1B1860A83" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "E31A6055297D96CA3330CDF1B1860A83" );
            data_len = unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "5D563F6D1CCCF236051C0C5C1C58F28F" ) == 0 );
            }
        }
        FCT_TEST_END();

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "14F7646187817EB586599146B82BD719" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "14F7646187817EB586599146B82BD719" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "A53D28BB82DF741103EA4F921A44880B" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "A53D28BB82DF741103EA4F921A44880B" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "9C2157A664626D1DEF9EA420FDE69B96" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "9C2157A664626D1DEF9EA420FDE69B96" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "742A25F0542340C7BAEF24CA8482BB09" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_decrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "14F7646187817EB586599146B82BD719" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_decrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "14F7646187817EB586599146B82BD719" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "A53D28BB82DF741103EA4F921A44880B" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_decrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "A53D28BB82DF741103EA4F921A44880B" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "9C2157A664626D1DEF9EA420FDE69B96" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_128_cfb128_decrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "2B7E151628AED2A6ABF7158809CF4F3C" );
            unhexify( iv_str, "9C2157A664626D1DEF9EA420FDE69B96" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "742A25F0542340C7BAEF24CA8482BB09" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "C832BB9780677DAA82D9B6860DCD565E" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "C832BB9780677DAA82D9B6860DCD565E" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "86F8491627906D780C7A6D46EA331F98" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "86F8491627906D780C7A6D46EA331F98" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "69511CCE594CF710CB98BB63D7221F01" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "69511CCE594CF710CB98BB63D7221F01" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "D5B5378A3ABED55803F25565D8907B84" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_decrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "C832BB9780677DAA82D9B6860DCD565E" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_decrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "C832BB9780677DAA82D9B6860DCD565E" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "86F8491627906D780C7A6D46EA331F98" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_decrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "86F8491627906D780C7A6D46EA331F98" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "69511CCE594CF710CB98BB63D7221F01" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_192_cfb128_decrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B" );
            unhexify( iv_str, "69511CCE594CF710CB98BB63D7221F01" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "D5B5378A3ABED55803F25565D8907B84" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_encrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "CF6107BB0CEA7D7FB1BD31F5E7B06C93" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_encrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "CF6107BB0CEA7D7FB1BD31F5E7B06C93" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "89BEDB4CCDD864EA11BA4CBE849B5E2B" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_encrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "89BEDB4CCDD864EA11BA4CBE849B5E2B" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "555FC3F34BDD2D54C62D9E3BF338C1C4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_encrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "555FC3F34BDD2D54C62D9E3BF338C1C4" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5953ADCE14DB8C7F39F1BD39F359BFFA" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_decrypt_perl_evp_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "000102030405060708090A0B0C0D0E0F" );
            unhexify( src_str, "6BC1BEE22E409F96E93D7E117393172A" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "CF6107BB0CEA7D7FB1BD31F5E7B06C93" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_decrypt_perl_evp_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "CF6107BB0CEA7D7FB1BD31F5E7B06C93" );
            unhexify( src_str, "AE2D8A571E03AC9C9EB76FAC45AF8E51" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "89BEDB4CCDD864EA11BA4CBE849B5E2B" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_decrypt_perl_evp_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "89BEDB4CCDD864EA11BA4CBE849B5E2B" );
            unhexify( src_str, "30C81C46A35CE411E5FBC1191A0A52EF" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "555FC3F34BDD2D54C62D9E3BF338C1C4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(camellia_256_cfb128_decrypt_perl_evp_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4" );
            unhexify( iv_str, "555FC3F34BDD2D54C62D9E3BF338C1C4" );
            unhexify( src_str, "F69F2445DF4F9B17AD2B417BE66C3710" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cfb128( &ctx, CAMELLIA_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5953ADCE14DB8C7F39F1BD39F359BFFA" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */


        FCT_TEST_BGN(camellia_ecb_encrypt_invalid_key_length)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdeffedcba98765432" );
            unhexify( src_str, "0123456789abcdeffedcba9876543210" );
        
            fct_chk( camellia_setkey_enc( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_CAMELLIA_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_CAMELLIA_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "67673138549669730857065648eabe43" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_ecb_decrypt_invalid_key_length)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0123456789abcdeffedcba98765432" );
            unhexify( src_str, "0123456789abcdeffedcba9876543210" );
        
            fct_chk( camellia_setkey_dec( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_CAMELLIA_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_CAMELLIA_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( camellia_crypt_ecb( &ctx, CAMELLIA_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcasecmp( (char *) dst_str, "67673138549669730857065648eabe43" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_encrypt_invalid_input_length)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffe000000000000000" );
        
            camellia_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_ENCRYPT, data_len, iv_str, src_str, output) == POLARSSL_ERR_CAMELLIA_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_CAMELLIA_INVALID_INPUT_LENGTH == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(camellia_256_cbc_decrypt_invalid_input_length)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            camellia_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "623a52fcea5d443e48d9181ab32c74" );
        
            camellia_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( camellia_crypt_cbc( &ctx, CAMELLIA_DECRYPT, data_len, iv_str, src_str, output ) == POLARSSL_ERR_CAMELLIA_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_CAMELLIA_INVALID_INPUT_LENGTH == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcasecmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(camellia_selftest)
        {
            fct_chk( camellia_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_CAMELLIA_C */

}
FCT_END();

