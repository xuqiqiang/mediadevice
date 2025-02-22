#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include <polarssl/sha4.h>

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


    FCT_SUITE_BGN(test_suite_hmac_shax)
    {
#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_fips_198a_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" );
            src_len = unhexify( src_str, "53616d706c65202331" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_fips_198a_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "303132333435363738393a3b3c3d3e3f40414243" );
            src_len = unhexify( src_str, "53616d706c65202332" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "0922d3405faa3d194f82a45830737d5cc6c75d24", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_fips_198a_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3" );
            src_len = unhexify( src_str, "53616d706c65202333" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_fips_198a_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0" );
            src_len = unhexify( src_str, "53616d706c65202334" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "9ea886efe268dbecce420c75", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "7b10f4124b15c82e" );
            src_len = unhexify( src_str, "27dcb5b1daf60cfd3e2f73d4d64ca9c684f8bf71fc682a46793b1790afa4feb100ca7aaff26f58f0e1d0ed42f1cdad1f474afa2e79d53a0c42892c4d7b327cbe46b295ed8da3b6ecab3d4851687a6f812b79df2f6b20f11f6706f5301790ca99625aad7391d84f78043d2a0a239b1477984c157bbc9276064e7a1a406b0612ca" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "4ead12c2fe3d6ea43acb", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "4fe9fb902172a21b" );
            src_len = unhexify( src_str, "4ceb3a7c13659c22fe51134f03dce4c239d181b63c6b0b59d367157fd05cab98384f92dfa482d2d5e78e72eef1b1838af4696026c54233d484ecbbe87f904df5546419f8567eafd232e6c2fcd3ee2b7682c63000524b078dbb2096f585007deae752562df1fe3b01278089e16f3be46e2d0f7cabac2d8e6cc02a2d0ca953425f" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "564428a67be1924b5793", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "d1f01455f78c4fb4" );
            src_len = unhexify( src_str, "00d40f67b57914bec456a3e3201ef1464be319a8d188c02e157af4b54f9b5a66d67f898a9bdbb19ff63a80aba6f246d013575721d52eb1b47a65def884011c49b257bcc2817fc853f106e8138ce386d7a5ac3103de0a3fa0ed6bb7af9ff66ebd1cc46fb86e4da0013d20a3c2dcd8fb828a4b70f7f104b41bf3f44682a66497ea" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "56a665a7cdfe610f9fc5", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "4e5ef77fdf033a5b" );
            src_len = unhexify( src_str, "e59326464e3201d195e29f2a3446ec1b1c9ff31154e2a4d0e40ed466f1bc855d29f76835624fa0127d29c9b1915939a046f385af7e5d47a23ba91f28bd22f811ea258dbbf3332bcd3543b8285d5df41bd064ffd64a341c22c4edb44f9c8d9e6df0c59dbf4a052a6c83da7478e179a6f3839c6870ff8ca8b9497f9ac1d725fdda" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "981c0a7a8423b63a8fa6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "bcd9ff8aa60be2be" );
            src_len = unhexify( src_str, "51be4d0eb37bab714f92e19e9d70390655b363e8cd346a748245e731f437759cb8206412c8dab2ef1d4f36f880f41ff69d949da4594fdecb65e23cac1329b59e69e29bf875b38c31df6fa546c595f35cc2192aa750679a8a51a65e00e839d73a8d8c598a610d237fbe78955213589d80efcb73b95b8586f96d17b6f51a71c3b8" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "84633f9f5040c8971478", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_6)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "4a661bce6ed86d21" );
            src_len = unhexify( src_str, "5ff6c744f1aab1bc29697d71f67541b8b3cec3c7079183b10a83fb98a9ee251d4bac3e1cb581ca972aaed8efd7c2875a6fb4c991132f67c9742d45e53bc7e8eaa94b35b37a907be61086b426cd11088ac118934e85d968c9667fd69fc6f6ea38c0fe34710b7ece91211b9b7ea00acd31f022aa6726368f9928a1352f122233f1" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "739df59353ac6694e55e", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(hmac_sha_1_test_vector_nist_cavs_7)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[41];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 41);
        
            key_len = unhexify( key_str, "1287e1565a57b547" );
            src_len = unhexify( src_str, "390ffdccc6171c11568d85b8f913e019bf4cd982ca9cd21ea730d41bdf3fcc0bc88ff48ba13a8f23deb2d96ec1033e7b2a58ca72b0c1e17bf03330db25d1e360fa6918009c4294bd1215b5ccd159a8f58bc3dc3d490eb7c3b9f887e8c98dbbb274a75373dcb695a59abd0219529d88518a96f92abc0bbcbda985c388f1fbbcc9" );
        
            sha1_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 20 );
        
            fct_chk( strncmp( (char *) hash_str, "d78ddf08077c7d9e2ba6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "e055eb756697ee573fd3214811a9f7fa" );
            src_len = unhexify( src_str, "3875847012ee42fe54a0027bdf38cca7021b83a2ed0503af69ef6c37c637bc1114fba40096c5947d736e19b7af3c68d95a4e3b8b073adbbb80f47e9db8f2d4f0018ddd847fabfdf9dd9b52c93e40458977725f6b7ba15f0816bb895cdf50401268f5d702b7e6a5f9faef57b8768c8a3fc14f9a4b3182b41d940e337d219b29ff" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "40a453133361cc48da11baf616ee", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "88e5258b55b1623385eb9632fa7c57d6" );
            src_len = unhexify( src_str, "ada76bb604be14326551701cf30e48a65eee80b44f0b9d4a07b1844543b7844a621097fdc99de57387458ae9354899b620d0617eabcaefa9eef3d413a33628054335ce656c26fa2986e0f111a6351096b283101ec7868871d770b370973c7405983f9756b3005a3eab492cfd0e7eb42e5c2e15fa6be8718c0a50acc4e5717230" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "81c783af538015cef3c60095df53", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "85d402d822114d31abf75526e2538705" );
            src_len = unhexify( src_str, "8020d8d98cc2e2298b32879c51c751e1dd5558fe2eabb8f158604297d6d072ce2261a1d6830b7cfe2617b57c7126f99c9476211d6161acd75d266da217ec8174b80484c9dc6f0448a0a036a3fc82e8bf54bdb71549368258d5d41f57978a4c266b92e8783ef66350215573d99be4089144b383ad8f3222bae8f3bf80ffb1bb2b" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "2aa0340ac9deafe3be38129daca0", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "545c6eecc5ee46fa17c59f91a94f81ae" );
            src_len = unhexify( src_str, "8fb7f3565593170152ddb2021874784e951977cfdd22f8b72a72a61320a8f2a35697b5e913f717805559b1af1861ee3ed42fb788481e4fd276b17bdbefcae7b4501dc5d20de5b7626dd5efdcd65294db4bdf682c33d9a9255c6435383fa5f1c886326a3acbc6bd50a33ab5b2dbb034ce0112d4e226bbcd57e3731a519aa1d784" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "3eb566eac54c4a3a9ef092469f24", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "4466ab4dc438841a9750c7f173dff02e" );
            src_len = unhexify( src_str, "2534c11c78c99cffaec8f722f04adc7045c7324d58ce98e37cfa94b6ed21ed7f58ce55379ef24b72d6d640ee9154f96c614734be9c408e225d7ba4cecc1179cc9f6e1808e1067aa8f244a99bd0c3267594c1887a40d167f8b7cf78db0d19f97b01fc50b8c86def490dfa7a5135002c33e71d77a8cce8ea0f93e0580439a33733" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "59f44a9bbed4875b892d22d6b5ab", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_6)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "0e3dd9bb5e4cf0f09a4c11600af56d8d" );
            src_len = unhexify( src_str, "f4589fa76c328ea25cf8bae582026ba40a59d45a546ff31cf80eb826088f69bb954c452c74586836416dee90a5255bc5d56d3b405b3705a5197045688b32fa984c3a3dfbdc9c2460a0b5e6312a624048bb6f170306535e9b371a3ab134a2642a230ad03d2c688cca80baeaee9a20e1d4c548b1cede29c6a45bf4df2c8c476f1a" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "12175b93e3da4c58217145e4dc0a1cf142fab9319bb501e037b350ba", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_224_test_vector_nist_cavs_7)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[57];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 57);
        
            key_len = unhexify( key_str, "cda5187b0c5dcb0f8e5a8beed2306584" );
            src_len = unhexify( src_str, "9011ae29b44c49b347487ce972965f16ade3c15be0856ce9c853a9739dba07e4f20d594ddc1dfe21560a65a4e458cfa17745575b915a30c7a9412ff8d1d689db9680dd2428c27588bb0dc92d2cd9445fe8f44b840a197c52c3c4333fff45533945134398df6436513cfab06c924046b8c795a5bd92e8d5f2de85bf306f2eed67" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 28 );
        
            fct_chk( strncmp( (char *) hash_str, "4aaba92b40e2a600feab176eb9b292d814864195c03342aad6f67f08", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "cdffd34e6b16fdc0" );
            src_len = unhexify( src_str, "d83e78b99ab61709608972b36e76a575603db742269cc5dd4e7d5ca7816e26b65151c92632550cb4c5253c885d5fce53bc47459a1dbd5652786c4aac0145a532f12c05138af04cbb558101a7af5df478834c2146594dd73690d01a4fe72545894335f427ac70204798068cb86c5a600b40b414ede23590b41e1192373df84fe3" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "c6f0dde266cb4a26d41e8259d33499cc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "6d97bb5892245be2" );
            src_len = unhexify( src_str, "13c2b391d59c0252ca5d2302beaaf88c4bcd779bb505ad9a122003dfae4cc123ad2bd036f225c4f040021a6b9fb8bd6f0281cf2e2631a732bdc71693cc42ef6d52b6c6912a9ef77b3274eb85ad7f965ae6ed44ac1721962a884ec7acfb4534b1488b1c0c45afa4dae8da1eb7b0a88a3240365d7e4e7d826abbde9f9203fd99d7" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "31588e241b015319a5ab8c4527296498", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "3c7fc8a70b49007a" );
            src_len = unhexify( src_str, "60024e428a39c8b8bb2e9591bad9dc2115dfbfd716b6eb7af30a6eb34560caccbbfa47b710fa8d523aca71e9e5ba10fc1feb1a43556d71f07ea4f33496f093044e8caf1d02b79e46eb1288d5964a7a7494f6b92574c35784eece054c6151281d80822f7d47b8231c35d07f5cb5cf4310ddc844845a01c6bfab514c048eccaf9f" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "1c98c94a32bec9f253c21070f82f8438", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "369f33f85b927a07" );
            src_len = unhexify( src_str, "ae8e2a94ca386d448cbacdb0e9040ae3cb297c296363052cc157455da29a0c95897315fc11e3f12b81e2418da1ec280bccbc00e847584ce9d14deeba7b3c9b8dba958b04bba37551f6c9ba9c060be1a4b8cf43aa62e5078b76c6512c5619b71a6a7cf5727180e1ff14f5a1a3c1691bf8b6ebad365c151e58d749d57adb3a4986" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "60b90383286533d309de46593e6ce39fc51fb00a8d88278c", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "e5179687582b4dc4" );
            src_len = unhexify( src_str, "ce103bdacdf32f614f6727bcb31ca1c2824a850d00f5585b016fb234fe1ef2cd687f302d3c6b738ed89a24060d65c36675d0d96307c72ef3e8a83bfa8402e226de9d5d1724ba75c4879bf41a4a465ce61887d9f49a34757849b48bae81c27ebed76faae2ad669bca04747d409148d40812776e0ae2c395b3cb9c89981ce72d5c" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "509581f6816df4b8cc9f2cf42b7cc6e6a5a1e375a16f2412", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(hmac_sha_256_test_vector_nist_cavs_6)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[65];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 65);
        
            key_len = unhexify( key_str, "63cec6246aeb1b61" );
            src_len = unhexify( src_str, "c178db908a405fa88aa255b8cad22b4057016585f139ee930388b083d86062fa0b3ea1f23f8a43bd11bee8464bcbd19b5ab9f6a8038d5245516f8274d20c8ee3033a07b908da528fa00343bb595deed500cab9745c4cb6391c23300f0d3584b090b3326c4cfa342620b78f9f5b4f27f7307ed770643ec1764aeae3dcf1a3ec69" );
        
            sha2_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 32 );
        
            fct_chk( strncmp( (char *) hash_str, "64f3dd861b7c7d29fce9ae0ce9ed954b5d7141806ee9eec7", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "91a7401817386948ca952f9a20ee55dc" );
            src_len = unhexify( src_str, "2fea5b91035d6d501f3a834fa178bff4e64b99a8450432dafd32e4466b0e1e7781166f8a73f7e036b3b0870920f559f47bd1400a1a906e85e0dcf00a6c26862e9148b23806680f285f1fe4f93cdaf924c181a965465739c14f2268c8be8b471847c74b222577a1310bcdc1a85ef1468aa1a3fd4031213c97324b7509c9050a3d" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "6d7be9490058cf413cc09fd043c224c2ec4fa7859b13783000a9a593c9f75838", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "d6cac19657061aa90a6da11cd2e9ea47" );
            src_len = unhexify( src_str, "9f482e4655173135dfaa22a11bbbe6af263db48716406c5aec162ba3c4b41cad4f5a91558377521191c7343118beee65982929802913d67b6de5c4bdc3d27299bd722219d5ad2efa5bdb9ff7b229fc4bbc3f60719320cf2e7a51cad1133d21bad2d80919b1836ef825308b7c51c6b7677ac782e2bc30007afba065681cbdd215" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "f3d5f3c008175321aa7b2ea379eaa4f8b9dcc60f895ec8940b8162f80a7dfe9f", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "e06366ad149b8442cd4c1abdddd0afde" );
            src_len = unhexify( src_str, "2d140a194c02a5598f69174834679b8371234a0d505491f1bd03e128dd91a8bca2fb812e9d5da71613b5b00952ea78bf450d5b7547dea79135925085c7d3e6f52009c51ca3d88c6c09e9d074b0ee110736e0ec9b478b93efb34d7bf1c41b54decec43eab077a3aa4998ede53f67b4ea36c266745f9643d5360bdc8337c70dabf" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "c19c67eda6fe29f3667bee1c897c333ce7683094ae77e84b4c16378d290895a1", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "01ac59f42f8bb91d1bd10fe6990d7a87" );
            src_len = unhexify( src_str, "3caf18c476edd5615f343ac7b7d3a9da9efade755672d5ba4b8ae8a7505539ea2c124ff755ec0457fbe49e43480b3c71e7f4742ec3693aad115d039f90222b030fdc9440313691716d5302005808c07627483b916fdf61983063c2eb1268f2deeef42fc790334456bc6bad256e31fc9066de7cc7e43d1321b1866db45e905622" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "1985fa2163a5943fc5d92f1fe8831215e7e91f0bff5332bc713a072bdb3a8f9e5c5157463a3bfeb36231416e65973e64", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "fd74b9d9e102a3a80df1baf0cb35bace" );
            src_len = unhexify( src_str, "1a068917584813d1689ccbd0370c2114d537cdc8cc52bf6db16d5535f8f7d1ad0c850a9fa0cf62373ffbf7642b1f1e8164010d350721d798d9f99e9724830399c2fce26377e83d38845675457865c03d4a07d741a505ef028343eb29fd46d0f761f3792886998c1e5c32ac3bc7e6f08faed194b34f06eff4d5d4a5b42c481e0e" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "a981eaf5de3d78b20ebd4414a4edd0657e3667cd808a0dbc430cf7252f73a5b24efa136039207bd59806897457d74e0c", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_384_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[97];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 97);
        
            key_len = unhexify( key_str, "9fe794f0e26b669fa5f6883149377c6c" );
            src_len = unhexify( src_str, "6010c9745e8f1d44cfdc99e7e0fd79bc4271944c2d1d84dba589073dfc4ca5eb98c59356f60cd87bef28aeb83a832bde339b2087daf942aa1f67876c5d5ed33924bed4143bc12a2be532ccaf64daa7e2bc3c8872b9823b0533b6f5159135effe8c61545536975d7c3a61ba7365ec35f165bc92b4d19eb9156ade17dfa1bb4161" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 1 );
            hexify( hash_str, output, 48 );
        
            fct_chk( strncmp( (char *) hash_str, "915ae61f8754698c2b6ef9629e93441f8541bd4258a5e05372d19136cfaefc0473b48d96119291b38eb1a3cb1982a986", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "c95a17c09940a691ed2d621571b0eb844ede55a9" );
            src_len = unhexify( src_str, "99cd28262e81f34878cdcebf4128e05e2098a7009278a66f4c785784d0e5678f3f2b22f86e982d273b6273a222ec61750b4556d766f1550a7aedfe83faedbc4bdae83fa560d62df17eb914d05fdaa48940551bac81d700f5fca7147295e386e8120d66742ec65c6ee8d89a92217a0f6266d0ddc60bb20ef679ae8299c8502c2f" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "6bc1379d156559ddee2ed420ea5d5c5ff3e454a1059b7ba72c350e77b6e9333c", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "3b10b8fa718840d1dea8e9fc317476bcf55875fd" );
            src_len = unhexify( src_str, "f04f5b7073d7d0274e8354433b390306c5607632f5f589c12edb62d55673aff2366d2e6b24de731adf92e654baa30b1cfd4a069788f65ec1b99b015d904d8832110dbd74eae35a81562d14ce4136d820ad0a55ff5489ba678fbbc1c27663ec1349d70e740f0e0ec27cfbe8971819f4789e486b50a2d7271d77e2aaea50de62fd" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "fc3c38c7a17e3ce06db033f1c172866f01a00045db55f2e234f71c82264f2ba2", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "4803d311394600dc1e0d8fc8cedeb8bde3fe7c42" );
            src_len = unhexify( src_str, "a10c125dd702a97153ad923ba5e9889cfac1ba169de370debe51f233735aa6effcc9785c4b5c7e48c477dc5c411ae6a959118584e26adc94b42c2b29b046f3cf01c65b24a24bd2e620bdf650a23bb4a72655b1100d7ce9a4dab697c6379754b4396c825de4b9eb73f2e6a6c0d0353bbdeaf706612800e137b858fdb30f3311c6" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "7cd8236c55102e6385f52279506df6fcc388ab75092da21395ce14a82b202ffa", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "aeb2f3b977fa6c8e71e07c5a5c74ff58166de092" );
            src_len = unhexify( src_str, "22457355dc76095abd46846b41cfe49a06ce42ac8857b4702fc771508dfb3626e0bfe851df897a07b36811ec433766e4b4166c26301b3493e7440d4554b0ef6ac20f1a530e58fac8aeba4e9ff2d4898d8a28783b49cd269c2965fd7f8e4f2d60cf1e5284f2495145b72382aad90e153a90ecae125ad75336fb128825c23fb8b0" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "fa39bd8fcc3bfa218f9dea5d3b2ce10a7619e31678a56d8a9d927b1fe703b125af445debe9a89a07db6194d27b44d85a", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "4285d3d7744da52775bb44ca436a3154f7980309" );
            src_len = unhexify( src_str, "208f0b6f2de2e5aa5df11927ddc6df485edc1193181c484d0f0a434a95418803101d4de9fdb798f93516a6916fa38a8207de1666fe50fe3441c03b112eaaae6954ed063f7ac4e3c1e3f73b20d153fe9e4857f5e91430f0a70ee820529adac2467469fd18adf10e2af0fea27c0abc83c5a9af77c364a466cffce8bab4e2b70bc1" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "fe7603f205b2774fe0f14ecfa3e338e90608a806d11ca459dff5ce36b1b264ecd3af5f0492a7521d8da3102ba20927a5", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(hmac_sha_512_test_vector_nist_cavs_6)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[129];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 129);
        
            key_len = unhexify( key_str, "8ab783d5acf32efa0d9c0a21abce955e96630d89" );
            src_len = unhexify( src_str, "17371e013dce839963d54418e97be4bd9fa3cb2a368a5220f5aa1b8aaddfa3bdefc91afe7c717244fd2fb640f5cb9d9bf3e25f7f0c8bc758883b89dcdce6d749d9672fed222277ece3e84b3ec01b96f70c125fcb3cbee6d19b8ef0873f915f173bdb05d81629ba187cc8ac1934b2f75952fb7616ae6bd812946df694bd2763af" );
        
            sha4_hmac( key_str, key_len, src_str, src_len, output, 0 );
            hexify( hash_str, output, 64 );
        
            fct_chk( strncmp( (char *) hash_str, "9ac7ca8d1aefc166b046e4cf7602ebe181a0e5055474bff5b342106731da0d7e48e4d87bc0a6f05871574289a1b099f8", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

    }
    FCT_SUITE_END();


}
FCT_END();

