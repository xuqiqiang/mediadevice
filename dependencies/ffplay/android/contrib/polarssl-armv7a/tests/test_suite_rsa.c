#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/rsa.h>
#include <polarssl/md2.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include <polarssl/sha4.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

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
#ifdef POLARSSL_RSA_C
#ifdef POLARSSL_BIGNUM_C
#ifdef POLARSSL_GENPRIME


    FCT_SUITE_BGN(test_suite_rsa)
    {
#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_1)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "d6248c3e96b1a7e5fea978870fcc4c9786b4e5156e16b7faef4557d667f730b8bc4c784ef00c624df5309513c3a5de8ca94c2152e0459618666d3148092562ebc256ffca45b27fd2d63c68bd5e0a0aefbe496e9e63838a361b1db6fc272464f191490bf9c029643c49d2d9cd08833b8a70b4b3431f56fb1eb55ccd39e77a9c92" );
            unhexify( result_str, "3203b7647fb7e345aa457681e5131777f1adc371f2fba8534928c4e52ef6206a856425d6269352ecbf64db2f6ad82397768cafdd8cd272e512d617ad67992226da6bc291c31404c17fd4b7e2beb20eff284a44f4d7af47fd6629e2c95809fa7f2241a04f70ac70d3271bb13258af1ed5c5988c95df7fa26603515791075feccd" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_VERIFY_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_2)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "206ef4bf396c6087f8229ef196fd35f37ccb8de5efcdb238f20d556668f114257a11fbe038464a67830378e62ae9791453953dac1dbd7921837ba98e84e856eb80ed9487e656d0b20c28c8ba5e35db1abbed83ed1c7720a97701f709e3547a4bfcabca9c89c57ad15c3996577a0ae36d7c7b699035242f37954646c1cd5c08ac" );
            unhexify( result_str, "5abc01f5de25b70867ff0c24e222c61f53c88daf42586fddcd56f3c4588f074be3c328056c063388688b6385a8167957c6e5355a510e005b8a851d69c96b36ec6036644078210e5d7d326f96365ee0648882921492bc7b753eb9c26cdbab37555f210df2ca6fec1b25b463d38b81c0dcea202022b04af5da58aa03d77be949b7" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_3)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "206ef4bf396c6087f8229ef196fd35f37ccb8de5efcdb238f20d556668f114257a11fbe038464a67830378e62ae9791453953dac1dbd7921837ba98e84e856eb80ed9487e656d0b20c28c8ba5e35db1abbed83ed1c7720a97701f709e3547a4bfcabca9c89c57ad15c3996577a0ae36d7c7b699035242f37954646c1cd5c08ac" );
            unhexify( result_str, "5abc01f5de25b70867ff0c24e222c61f53c88daf42586fddcd56f3c4588f074be3c328056c063388688b6385a8167957c6e5355a510e005b8a851d69c96b36ec6036644078210e5d7d326f96365ee0648882921492bc7b753eb9c26cdbab37555f210df2ca6fec1b25b463d38b81c0dcea202022b04af5da58aa03d77be949b7" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_4)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "867ac26e11a13b7ac34a42a1e177648692861226effb55bb597fbde10f299bf7fffd6fc8ddb2a46a73b97b67387a461b23e1d65dc119366286979add615b926b9272832fc0c058b946fc752dcffceca12233f4c63f7897cbaa08aa7e07cf02b5e7e3e5ece252bf2fe61d163bce84c0e0368454a98e9fdebf6edbd70b290d549b" );
            unhexify( result_str, "3bb7b1c5f3391de4549e2e96fd33afa4d647dd90e321d9d576f3808e32213e948b697ef4fd2dd12923de6ec3ffd625078a57f86af38dc07052bb50547c616ed51fa1352b3ab66788408168d21263ef2d3388d567d2ce8cf674f45491ab2b0319d47be1266bda39e343b2a38ea2d6aaaee6c4465aee1d7bb33e93a1c40a8e3ae4" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_5)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "cd810e97dc21095ea7a0238027a7bafd343e01444785ea9184a44a79f80438c41fc0b57aa95693407da38fe5ff0ec1398e03361e51a3dbe134b99cca2df0cef1c444ca54d2b7db2789455b6bb41918c24001fd82fc20ee089de3f34f053699c1c5f7954ce0aaabb9d26fce39d032894152229d98cf64ecafc7089530073c61d9" );
            unhexify( result_str, "7b5fba70ec5b521638f182bcab39cec30b76e7bc017bdbd1059658a9a1db0969ab482dce32f3e9865952f0a0de0978272c951e3c015328ea3758f47029a379ab4200550fba58f11d51264878406fc717d5f7b72b3582946f16a7e5314a220881fc820f7d29949710273421533d8ac0a449dc6d0fd1a21c22444edd1c0d5b44d3" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_6)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "44637d3b8de525fd589237bc81229c8966d3af24540850c24036330db8007e6d19a19486018b2b02074da590aaba9d2c8848c0a2d1b6de4dfaf24025b6393df9228008f83f13cc76a67cfbed77a6e3429342824a0b6a9b8dd884094acc6a54bbc8c8829930c52fe39ce5e0dcd02d9553ef899d26eb6cae0940b63584e2daeb3b" );
            unhexify( result_str, "38fc4f6f0430bb3ea9f470a4c0f5cebdabac4dbeb3b9c99d4168e7b00f5eb294ec0ece1908eded1f3e14f1e69d10f9feb425bda0c998af945ef864298a60a675f0bb5c540a7be3f534d5faddff974eea8bffe182a44e2ee1f4f653e71967a11869ee1a850edb03cb44a340378cb7a1bc9616d3649b78002b390a05a7e54edec6" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_7)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "d03f12276f6ba7545b8fce719471bd253791878809694e8754f3b389f26c9253a758ed28b4c62535a8d5702d7a778731d5759ff2b3b39b192db680e791632918b6093c0e8ca25c2bf756a07fde4144a37f769fe4054455a45cb8cefe4462e7a9a45ce71f2189b4fef01b47aee8585d44dc9d6fa627a3e5f08801871731f234cd" );
            unhexify( result_str, "d93a878c1ce86571590b0e43794b3edb23552797c4b8c9e3da4fe1cc4ac0566acd3b10541fe9a7a79f5ea4892d3069ca6903efb5c40c47eb8a9c781eb4249281d40c3d96aae16da1bb4daaece6a26eca5f41c062b4124a64fc9d340cba5ab0d1f5affff6515a87f0933774fd4322d2fa497cd6f708a429ca56dcb1fd3db623d0" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_8)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "b2f2e6e09fd19b0a8c06447554d6a236c69e2b334017488881d8c02ab81d74cae0c64efd50a374998eeec162651975e637cb2ba594250c750a4943253f1db0613e4ce1d50f8e3e968a2a83bd6cb97455ab2ccc77071076b3e211ffb251bd4c1a738b88b2021c61c727c074ce933c054acbcbf4f0c362ec09af38de191686aebe" );
            unhexify( result_str, "a853e67f928281d11506c9d39e5ea9b2d742782c663c37d0a7c9e9fe15379cde1e75d94adbfb1ca08691f320af4ff2b0a29a4d2ea10a20cb95d85f3dabac3d56cca9039c851d0181408c00b385fc82cafa4cfa7380d0c2c024fb83fec59d5ee591d63806dcb18b21ea440c3d3f12c1e7795eb15b7ce4c4b288d646cf1d34bdf1" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_9)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "647586ba587b09aa555d1b8da4cdf5c6e777e08859379ca45789019f2041e708d97c4408d4d6943b11dd7ebe05c6b48a9b5f1b0079452cc484579acfa66a34c0cf3f0e7339b2dbd5f1339ef7937a8261547705a846885c43d8ef139a9c83f5604ea52b231176a821fb48c45ed45226f31ba7e8a94a69f6c65c39b7278bf3f08f" );
            unhexify( result_str, "e27a90b644c3a11f234132d6727ada397774cd7fdf5eb0160a665ffccedabb8ae9e357966939a71c973e75e5ff771fb01a6483fcaf82f16dee65e6826121e2ae9c69d2c92387b33a641f397676776cde501e7314a9a4e76c0f4538edeea163e8de7bd21c93c298df748c6f5c26b7d03bfa3671f2a7488fe311309e8218a71171" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_10)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "55013a489e09b6553262aab59fb041b49437b86d52876f8e5d5e405b77ca0ff6ce8ea2dd75c7b3b411cf4445d56233c5b0ff0e58c49128d81b4fedd295e172d225c451e13defb34b87b7aea6d6f0d20f5c55feb71d2a789fa31f3d9ff47896adc16bec5ce0c9dda3fde190e08ca2451c01ff3091449887695f96dac97ad6a30e" );
            unhexify( result_str, "dd82b7be791c454fbbf6f1de47cbe585a687e4e8bbae0b6e2a77f8ca4efd06d71498f9a74b931bd59c377e71daf708a624c51303f377006c676487bad57f7067b09b7bb94a6189119ab8cf7321c321b2dc7df565bfbec833a28b86625fb5fd6a035d4ed79ff0f9aee9fa78935eec65069439ee449d7f5249cdae6fdd6d8c2a63" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_11)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "f4a990b8d434a5914340c0ca3ca4e4a70856c55e13e938c1f854e91cdef54c6107d6d682a62e6c1ff12b1c6178ee0b26b5d8ae5ee4043db4151465727f313e9e174d7c6961abe9cb86a21367a89e41b47267ac5ef3a6eceaaca5b19ae756b3904b97ec35aeb404dc2a2d0da373ba709a678d2728e7d72daae68d335cbf6c957d" );
            unhexify( result_str, "d8ef7bdc0f111b1249d5ad6515b6fe37f2ff327f493832f1385c10e975c07b0266497716fcb84f5039cd60f5a050614fde27f354a6c45e8a7d74f9821e2f301500ac1953feafeb9d98cf88d2c928413f337813135c66abfc3dc7a4d80655d925bf96f21872ca2b3a2684b976ca768fe37feae20a69eeec3cc8f1de0db34b3462" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_12)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "c81f04c79982971fa176d64e8f7f8812f86a94c49e84672ff10996a2d6dfc444a884c7a87c4606a1aab22558894ee59b798b457827f5ee0b0cadcd94371902cc4ddaf97acefed641997717bcb3cc74cd440f0a31e20fb95812cecb740c36d6d1bf07e3641514cfa678aff2a39562ff4d60e02b17583a92bf0c56d66bde9e09f8" );
            unhexify( result_str, "52111f4798da3c11b3c74394358348ab0fc797bde99080f238d33a69b04b08ac2bd767b33872473943e23af27ca32fd568a43a8c7d6cc55b4fbb380212fdfcb60487e20694d4287e233efdf7b04737c0037a592d03077801828b051998c42b9f9e2420063331d5b2349918a64d8b65b21a2011ee7318fcef48aced95b8ddf501" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_13)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "a97824871770b79da979a111f6decfb1dd11bd946cfa800b008f0ad5aea5aa92e205d27a46c31d4fe6cb909091bd21f082fb75074000ee46c2f3e530d77b34c7c5d6f8453025950d3e0afae1f9752655f5bbea8432e9f1014357ff11b08076179a101e4f9d3f25bffb5e656bf6afe6c97d7aa4740b5d9224cde4dede035a7768" );
            unhexify( result_str, "d5dcd27c74e040ea86f106b63d3275fa7b7e98d2dd701f38ec15fc7301b72df127f6d3bd5571253a0b9e0e719d7d522893896941a1aeccc697912282b5308d829b91905b5dd7b7e1b8fe27e2bd4003b09dfe7fe295f8a43c076c0cb52f2aac067e87de7ffe3a275d21a870c3dfc9b1d06d7f018667de9eb187bdf53d282e5d8b" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_14)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1024 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "e28a13548525e5f36dccb24ecb7cc332cc689dfd64012604c9c7816d72a16c3f5fcdc0e86e7c03280b1c69b586ce0cd8aec722cc73a5d3b730310bf7dfebdc77ce5d94bbc369dc18a2f7b07bd505ab0f82224aef09fdc1e5063234255e0b3c40a52e9e8ae60898eb88a766bdd788fe9493d8fd86bcdd2884d5c06216c65469e5" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4ce61930c79dc017c2dea0c5085d73a3b0e4a6f341e9a5061a6658af11e5edf95bdad915ac3619969e39bee15788a8de667f92f4efc84f35082d52d562aa74e12cc7f22d3425b58f5056d74afcf162cd44e65b9ee510ff91af094c3d2d42c3b088536d62a98f1c689edcf3ea3fc228d711c109d76ae83d82d6a34dcfbad563cf" );
            unhexify( result_str, "27280b92eab5cbf0d787ff6fa6b0151d6610adfd25116113f2f186f3f8d39736d91ae510ec2bd96f2de135aefda79178138696dcc6d302e4a79ddabbe16e39ab96075776afce863e84a2e6013cb457e4047e22d43f67bf64ae5e1d844a7c12ac696efbb3cda7c0e0aca71f8a7ada9a0547bfaefe1ba2e04058c672c803720dd9" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_15)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "224ecd3b630581da948216366c741015a9723c5ea43de67e28454d0a846f54a6df167a25cc500cf21f729aaefed6a71a3bdba438e12e20ad0c48396afe38568b70a3187f26098d6ac649a7c7ea68ed52748e7125225102216236a28f67753b077cfd8d9198b86b0b331027cb59b24b85fd92896e8f2ff5a1d11872c2e6af6ae2" );
            unhexify( result_str, "1f7938b20a9cd8bb8ca26bad9e79ea92373174203f3ab212a06de34a9a3e14e102d19a8878c28a2fc8083a97c06b19c1ae62678289d5d071a904aed1d364655d9e2d16480a6fd18f4c8edf204844a34d573b1b988b82d495caefd9298c1635083e196a11f4a7df6a7e3cc4db7b9642e7682d22ec7038c3bad791e1365fe8836976092460e6df749dc032baf1e026684f55936beb9369845c53c3d217941c1f8d8f54a32333a4c049c3f2d527125778032f5d390040d1d4cce83dc353ce250152" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_16)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "6ecc722d233dad1aca45e6bc3e1a0b99fb1f89c0ec63bc657e6aaacbf931f267106cff42b712819f341b1ede798964a0b1a5032c198b391111e88d0d7303c02e23fa0137e74e604579a285b2dbc0a23aebdda65c371eb403125bd366e822e72dceffe0d55dfa3155c16283020dc9abb0d150da1aef251484aa49e49e00974dac" );
            unhexify( result_str, "339dce3a1937669d9fb14c4f652378861fd5adc4da88eaf833b16020b55a24ddc83b7ae3395a9a49b426bb9a4170cb765b02652faa9594b457aeefdae4f802e93d8e65c687ddc723701465a5ef19249ed5d2617b5121c58557b34eb99a663bbcf4453a6e1db5d88723de449fcf58ca8ef514daf08cfdc71be155bb3d0724df0c0a6fd5aa7737433cc376640b9b8b4c7ddd09776bae0245729cddb56e36f28edad6aecaed0821ec8d843a96348e722bf0a84cf060a793a2179f054138f907d0c3" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_17)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "72f0b1ae27e1f5e5bfa15ded204c2c54b47b2420750a3eb5471f9ff98b67c8b5f1a30d3f8d6448562e12ce4deb33a26cfeeae993d6be9e20679d8713c5216870f11276e5f22b0ead2821a7b4dee106fc1e19b13fc9fba5d6e73e4bd93b65a9881a43d5e97ebfb0b357d5d06b21ddbecdbb10626d7748bb9e6e07d49316bbf3c4" );
            unhexify( result_str, "8117a6897e14c183737661cf5741350a84ae00495cd9ee8fb033582e559f79701ab424706660515ee5821a69a6850647ec641676a625d1a3899932aaa52161fbc0c0a825db82fde0585b3c9b9c16de43e26da6a30fe5a601dae68bded1e29ec34557b5f6962efb10b9450d6f096655f68e8499cfa16a0adeb9075e7b91851fef84243132d08273d35d01ad89c17e1e6e4deaf1cb233050b275fa9d2cae57e9e1a0e23139267040aa39b6abd8f10fa1cec38ce2183573ddc11626fc262e1a0ced" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_18)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "f80c94a2b53736978adf041886ad97ab2aeb9e91c08bd4eeef6b2f2b8dd75a99b4506657188bbd7597bd5759121630627c8bf9cc30d90dd488c7a81cabab5350a62fa30abf5523f305b98f2c2c1743ec980cf26ab8219bfd9505b981ab1abbfef733b384519d5259fc5c14577cb6b88fa7f6f332ff6a65b23faecc24342c78e9" );
            unhexify( result_str, "6b49553ed964ae196a41ea281f4d2a250ce7d1e7434e45cf6a82f7bed17554f39c3f0241e0364702fcb87475eb0c0839ffd2180890fa05b4bbf31bbfa4bf5119dea0c9f88e1e9617fcdadabc6fa1945136cc66e039b905d78ed365c5806d38aec88b3edfb86c05ff446dbfd51d7cd75cbf8d3b85154c783765386f51637532221f52429db5612dcc034968bb8feab7dc6f5ed1f2feb557f6dd49c980296117be2c4195ec7b6101ea767df9d16a56fc9709b49308a54dab63dbc4d609f959ce17" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_19)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4eb97094bb42aaa58b040bd06a8f324396b9eca9e39359b7039c4a010434ee131a53aebd9f7a55ae58ea7444fa1505a3ec524e054fd408513cddc1ee4c2f7fd95ec4a6f594be1ba39fa1aa933dc0a5dafff5ce44509577ebb3a3e8084c44010aa27321e5a3f646ade99175633b795c0f570b360eeebeefaef15788f80b5cbecd" );
            unhexify( result_str, "2b8b794a8621d492eec18a4efd239e0e077c89340a34b0fdbf467f2bf3112c7f33d00ee736f2988af8569c1a74891efbefa839e295fffdf4d908c1ede61a861a4d24b154a09d1b3f923fd2bb7906994cf82a97da285bf48e61f90cc3596f9350ab9b66a216ffca323195bb213f5a77fe8c697475595a1857dbee58128cbf1be7cb220229ce52766fefd88cc129ad5cbbdcd31fb4eede6c4fdd3193a9aaaa54362bcea4082981d9b7c40483814828f3297d95ad933c76f31c47e37a93ffaf0d4a" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_20)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "a3edb0f52c6166d7b76e71634761f402337c3e9667549d00cd7877e6055396b35c54c4dffc4c987060178fc10b7e5e827a5c870057002ba6efd31fc4e63a429029be0d6b256b6b653775cb026322743f48e319d053c4aeac34077acb8e0c6c2ef375b2210f8788bd23d24eb0b614de41875b1c8ec56acf18825eaf826691be96" );
            unhexify( result_str, "180630d2f4dc91ddb1159978e278cda7ac4b178e82477f9770c4d2e1c5017d2f222348658044c1be4cda24ce3c9ba3d423536a39bf60324c1b30eabdad700b0982e58072f7e18216e7e4c07e17674ec3eabcfbafce317d2f539f129902d80031ca201a8b325629a96ca4a70b51294c2fddd1d0aca1537d7d8b780e1e62d34be2f98104d876a4990396c8628e6498d9651f468bdf1139664eabe9166efbe909bf87d7305d5f60f1acc3599ed339fcf4e009fbad4059af1a50264cb0a4ec1d23f3" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_21)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "ac58fd024208d7f045d81a56cd55aad40ab86b0d216ab55136c7027aca23ea13480a52c0dacce0d98139b25965aa4ff76a41dd92037195d24bc0750d52cb3467b48b7b3e71d852c5f82bd9ee85a8388ead5cd8bc38c3d4792e8daa9734a137d31963e245ad3217fad235f7dfd5584de0fe91c4526568588e08b60bdf1badd99f" );
            unhexify( result_str, "a142b0d9456f8f4772675265a08613a66c416bd1ae712975c69d9ca5fb8c1be9c24359a04fd15460bf6136a8a11f13e3ce2de2171524f10cb715f0d71e3db15281ab99eadbe86cf8c5c518162c638ef27a4f7bfb4a1a3873f3c384a5b1c3b4966c837b9d8d192ac34e03943b7ae191355aa1ff3b9cd041bb2668f1f81cf0d015b3d3608cd9ac79398212c0f132f1bd45d47768b999fcf3c05fe2069593ceecedc851a7fc465abcfef0fabba9b9460153f6ba8723a5c6e766c83a446aef3ee327" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_22)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "027f767928a5821e2723d6f36c43e6b498b6f0b381852571794a096bd49f1c36a4d7bacec7ec402c24b970163169173bb930ec7fdc39bc9457dfc4ca051f5f28a64de1bbe007c22e8368ff9b117dbda17efd2fb73434bbbf5a4158df56813b8c904bb2e779de504dcd974a291568210d6f85810291606a1c0cd88d51ceadf98a" );
            unhexify( result_str, "0676e64daaa18f4af46e9dfbe234db389b8a527b0fe1db97eb7f404e3155226cba70d318800f83160fa1aa19916e5c09f079331079f18cb8ab1a4b884cb28501824974f683ed2b9babae9f8c15bea30802805c6b2152119764811bbf5f3994d2e97fa2fe8c5ab15a23c14d7ae56be00eaa8bc26678481ff5ba59b0acfb0e43341bff9fc638e5625480a73dbc5d8d13bd2b9e64037c6b79df0c60869980c6a22ec46f80fb859cb4ee5d2032ac1fe538cfd85c70a7f33b4af50a93395917c2cfb6" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_23)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "06dcd9d4c056b6a45b9ed2ae5f6c1cfa43aae06fe01ee098264aa7a80e901abbcf9a505e55f9a352ef0c078d48249b8298e57ea21bf0e423c3bf69002acfa541ca05007c704bc79cee7a80e1107c7b28d2b2aa6dd093b28efe9642519952a4a95ee49235f9924a0ac0aee5b2a1bce47459d70cd6e75074614199dca44561407c" );
            unhexify( result_str, "5e08f399258e6de075b67a0a6a822ceb21b1eb7a0342eca6a4295739f644547dee3456243cf32bd6ea6f357c88632508457130f3dae04f7806efaed43d1d501e16c961dfbd6c71a42b480e95c7027f8275063d05a9aac3eef0520867b9896ebe8ec358f7d121beb4e61ddfdc3dcd835dfe265f2ba68d300ef566ed1284f9f3d7b1af363ed47bfa2e5f0492925444df7e5fcb1e79e690c746117650b543a5e82c39553552f0f44e617b5cf773c533050f4129e893ac22af69b1eb9afb4b5ba5f5" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_24)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "1240028c6d7ab3992ada0e5ca55ee4f3d62f8de575302d5861d73685423c2e6a6d6fb3be090fbc2a701821b6d8fd5e8233f794b6549cd0bb52b390ac31478307bffa91a9bd9c1bf93ffc846356fef008ebee4bb3ee148e0fb1893d188e4934d0d088a433d14a596c5f2e3e49648a22edc6bdbcc58dc1edbd440046b3a169ca2b" );
            unhexify( result_str, "a003ae9cf0704d58763b214f20446ecc4099c566f25384e28d0dd6540c58705fc8d0bfe1ceaa06096ed1e230146edb82056e39e6727abec09f25e44079b6ce1ca2c6a540dec7aa34444d7d435f41e5fca9b0bba62759ae2780638e5160e031bb60409c2e85674ac7a776b444b37b9d7f4dbaa557e88b8562a584f2dbe90729b241aede95dfcc7e05b10deef06255cb89f0e7ccff23354818756a1f8bb9f00fd18f6cd22ca1b4bfc38027562bb37562c77c7883b5d735170d75521195fd3f2bd3" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_25)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "67922a8b9cbc95cf7c555ff2d73cfc62ee04c3f0df9bfc8f64293a58bd3bebd2eb212d711f94e35c729d0873d6b244914d21bd0e59b23089b38740e43f480e8f407d090ac93b08a57403968b55e78cfe31eee6e4ecbacf834168fe89b6b8454fce6e675e80f82b33e850ae3f3d24fd320335e37981fd000576941b4f08d4ba99" );
            unhexify( result_str, "2c6b301852cc55a993a933e2c080eb9dabfe19e9dc3571066caeabed1492d3501cd838de1c01784932df7a5ad5bbfb48c78f53a45f76e9812d046f23bd968495ef7e981e5add4acfc538fe33a5205de74bb37d3d9b6b87b2d174e85a73f216fd67d5738fc469dff7ea6b852e8dd08bc8df036597372d4d51185e6f47a45fbe1b9bdb06a4018783425ec95294de41f27235ad3b3263a890b8b62b17410a9bb08673393ff205a866ee2057e99c6517c6bbc84f8d87717b83d6f64de7ee215e1e8d" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_26)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "1428b4a449698a994ef84c46a517c3aa6359c48e4264ef65f1f69d77ae26133e17edfc103de416fffb4f2bfe865b434544a418f6e2faca00a165d443f0663ff64080154614f7194057d8b5f1f33934cc9fc2314cf86d4fdad4892bf0d3058f7f37ebe98ef52bfb240b9ad369153afe081bbcf9d7ae43e8ba336b8ac57e8a6da0" );
            unhexify( result_str, "8e10a1ae470e6e57a8d234185f78fdb600cc636c41565a9f3694a84ae102f6251984f54d11a7785fdcfdfaf80a821e05d57ef6b8edc03d9076755779322fd53eb98c805da77dc9316744e393c2fecd291a7e6043b1ca89fd8248f661e1d53110211b91edb41b31e848cde1115d8afd9963ebcc36aff5a27085949f0781bc69167c140ecfe71c44aacaf4123e557eaf2b528c6d0ea875b4ceefa942fe338af8df10562c438af04cd7521da912b3e3899cef0d75722161be6abed5e4e9009dbf40" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_27)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4871adc05f6b3ecf296680b0dd8d86715b0d5264c064008037dc410512520b5f193c8f4d21eb6c42e10d220c0275c9b3751f03a4096e2f0e3db9df8d52068c06a51589d23ca1361e9fe27691e95663301ec1407fbf73aee99cc92362eaf6994b95038396d815052a0aef6489bbb7bcb0fffdf13f0af9e7d9fd14f6ce00ab98f7" );
            unhexify( result_str, "180caf03781b391aacebe5b3f5e1d3b01c68a00df4ecfb6c4bf14217aed7cfca0adac099ec1d6e1f0b43b09b86788533fee6691d773807af0df6cc3bbdde3cf34bf5b848fa59c8bc10227cc3eba3452a85e0520fccdb2d8d32dd99672d302756a2d7f7f2693db3a48be17bd34d9d891f4ba44449c5bad1de91b788f524500a7703cccbaa77b9fe8791f5c8aa7b8f055336f28fcfc01733712e33cfb3d33fe71ddb9ced2a31931ec38007f5ad4a0d19acc428124b0e5ee6e0746fb33c1a4d90c8" );
        
            switch( SIG_RSA_SHA1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA1, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_28)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "3bba64de38438a71b95ab9c94539d5870c1fb08d7a9937600c00e9d063438edc97e625d0cd4b1eb00c31c9d94c7a0fe6d03160d1b6cbec5acdad16ada6ef253fee603df9faca8f98a477cc5456f3dfbf6414dbf19f3832e227ce291780188881e82e96a2e84744f12a34a9808a2daedc6fd00b345c6772bec26a095719451e6a" );
            unhexify( result_str, "8c846e75e32ce5f9964bdd8f6dcf1d2996a646b233bcf1bd6394e13e856691b89bedd18290a0f9f7c90dca307271b3108e795340490513b25e6789e93722c65ec064b4c43457295a31d1f07dd605e133fd6eaafc58cda132df2939f5f693e0205af34550afaa137f3e482885e50dfb48333a15c0821e7a19642acdddc6fea3c7487c691246a2b083dac439889d5ae741b7e08c47937530b4b069f1a260cd07fe4a0ddd530ab11534fb805e9b562118ee0e97932966008aadfc83f3b8a10de8ee" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_29)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "f7857ce04bf4292ea1755f9e587822372f4dcdf10bddfc0ff498a8af60ae94a0b482e873085c1cd52a5d181ce6b99a1f8520d74b947d65f3e7e358e8ddc4ac4ae465e39d408eee1f09865159733f83f553cd93cfde1c114fb3e32cf51cd418359016b3867df467b645d752808671a4609f3c49a67023c9ca617e6cffa544a10a" );
            unhexify( result_str, "9677300bbee003be3c445634f8ed5beb152b63f46f84cf5a8e721e0fafe8f3f7e99a6d50741f23f449d3026da3e8a7ac36be99ab44831803486ae552f7aa01f075287829b231d2d0840908e09081ae177ed888fe46a9d937a0871eb5d52ec541c8411c4cbf7efea6ca213b12cea513b0739eedca7c9473e10a7796936f4eaa0c5d3a9013ca5536781ac68eb2ca5779144de23da2e9875114aca885b3219dfc292d73940c5992ea3c4882889e7543430652860e441a01a45d9f4005a012421493" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_30)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "ca312774f2756ac2019f213a01a63c9a0b4a49ccafecf25e97a4c632668e3c77e664f4d7635241f25205e50c37061b02c546db8346fa597c3da8cfd44a827c5a4ff4ecfcd1797b39a1b215d9bbb93fdb6eb35bafbda427a5068888a6e19f86224b0897490491207e35ce39085668b10b4fb851b7dd9465c03869790ef38a61b5" );
            unhexify( result_str, "a202c33eb831b9d8e818b6c3bcdb42818e1d9c22a06ddd73a17a21e49d18cda44df349a066477cae068e1a5d2b518b0885e889ef796ca9e6f42a69ac755b8a6405fbaef93fe0130d98de35d689addfee3eecd26658903f774bda481c3f40ee0e9569a3c3e2da7ad576c7de82159d933e36fa29cfef99367005e34ab5082d80f48276d37dabc88dbb023bd01585329d2ccf417f78ec508aaa29751007d31f1669296b981d44c8fa99130c5df7a071725b496859314aaf9baf0ebc780355914249" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_31)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "10001" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "2abe079077290ceb6c80ac5c61062ce8da814b1fb99a1a9fb2860ed900e6541856ec64bf19c0d9d1cc2280b7cc50af3e3d2ad8e044945d44761ca60891dd72bd6aa26a33274ffcf7ae7d661b5e651135fcff21aaf06b4a2db18fe5827e0243884f2841760b9f1c65fbda870f7f0cfbd6ff484f0825e688614928f2d12d1e7080" );
            unhexify( result_str, "402631f3cddfb02cc4d9cb58ef1ab6726bd787a50e12e98567c9702bfdf47af85904aec5a2f6c5df9a10f08f90f93728eb090ae2ac21ded9f38faecd8195f3eb3d4107521b1cee956e7a214245b038adae912fa35ec97cb3bdc41352e8aaff80173561284cb740f999a3cd6653a6c3d5a3f911a416f41e2155083982c99eb5998a0a74d77f1ae999d901ee24a7f2c424179a3f92b07dc0b3498c1884e60677bee0175e810b426c4ad008d2743cd19b00b33177bf8be3fed7f7406e1bce0c2ea3" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_32)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "da9505809dc92cfd8e01a1857dde52df6677c40d98f4577c1659ca7d3e9f01f9a809065f51b54fe2f9723fe2c9d1eea7397f2d5531d1c51c6ea100b028596bf9f24dd90be14eab58f07b4f24a35b073aeb29ecde4a6f320237d7adbdc43d94f87e08866b95bbcac83dc7db3553a42400441f088e2bf6259539a2da8b5a74065f" );
            unhexify( result_str, "57edd0560df9840a25c28ff6d254e432395a5cd2d92248b3b44d7eab0fc65b3c4e545a916a8e90ce89745119db9ec9799aa8890f5250fb589cfc12dac1b6e406a39bc3b3663892da5354ba453cbd5e4c89bdce82d0ffe97052a03a5c3308819c1139ebc780c13cf6dc1477faf734abcb1db3fafaed6f22885c9c0222ff5deacb8cc6d027f2e959c3075011b382e88c4b27b83b4f2e6fda022e331c3602d19f5ac7bccfe95ea1e93d736dbd918ae5b1f468cd0b5b536a2f918d5e27a0757e75b7" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_33)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "d0cd038c65b3acca45822eaf91ea5176e82043268876dec0b62e2abd619023b7023abc67c6b823cfef5447b8772f985ff7910d6cc87e6c23688ac6de1fee40bbe2da1a92770de92adaa427ace02fee571a0a0176fceb0c8f3eb72dde839ab201395625f5c0db8641ce19d7711212dec61733262c6ce4476c025e67a3d5bc01f3" );
            unhexify( result_str, "2f30629c1117d013bb36e6099dee931dcaf0a1032b07ec23e2b262898a8945e569c9573d81e22bb0a5f8a28b0d7b8ff01367dd7f089c68ed1daa11cf53a96ee91b38e6b839b6e90bea34d14b78f5d2c7629b68c5b4f2ecfff66b483b2233cb14f95df533c867a2b610aebcdbb7ea3109aaf2f5762ab3edc2571deccc7da0c9a5b443ca2b924c0f18de7bbb736a08fed3916795018a436a3ae62c85d554a53a6d48623908e06e7d275f4251d3b3bd530bd11e155dcf2b5c2adf030cdf931ae749" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_verify_v15_cavs_34)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "a59d9b7269b102b7be684ec5e28db79992e6d3231e77c90b78960c2638b35ef6dbdac1ac59e7249d96d426e7f99397eabc6b8903fe1942da580322b98bafacd81bb911c29666f83886a2a2864f3552044300e60cedd5a8c321c43e280413dc41673c39a11b98a885486f8187a70f270185c4c12bc48a1968305269776c070ef69d4913589a887c4d0f5e7dd58bd806d0d49a14a1762c38665cef4646ff13a0cd29c3a60460703c3d051d5b28c660bffb5f8bd43d495ffa64175f72b8abe5fddd" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "11" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "0b4d96f411c727a262d6d0ade34195b78603551061917d060f89add47b09dfe8715f4f9147d327dc25e91fe457e5d1a2f22cd8fe6fe8e29d2060658307c87a40640650fef3d4b289a6c3febc5a100b29a8b56623afb29fd3c13ea372bf3c638c1db25f8bd8c74c821beec7b5affcace1d05d056a6c2d3035926c7a268df4751a54bc20a6b8cfd729a7cba309ae817daccbef9950a482cf23950a8ca1d3a13ddb7d8d0f87ad5587d4d9ebe19fe93457597a7bdd056c2fd4cea7d31e4a0e595a7b" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_1_sha512_1536_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "c8c67df894c882045ede26a9008ab09ea0672077d7bc71d412511cd93981ddde8f91b967da404056c39f105f7f239abdaff92923859920f6299e82b95bd5b8c959948f4a035cbd693ad83014294d349813d1ad57911a6355d0731fe3a034e9db" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "f15147d0e7c04a1e3f37adde802cdc610999bf7ab0088434aaeda0c0ab3910b14d2ce56cb66bffd97552195fae8b061077e03920814d8b9cfb5a3958b3a82c2a7fc97e55db5978b47a922156eb8a3e55c06a54a45d1670abdfb995489c4d0051" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "bd429bb7c3b00bbea19ba664c0f8172d1a73c3cfa05e2ed656d570c1590918bb7e372ed25e2cd71395ba0a9b1a30f3ee012ffb0546cab8e3581fe3e23f44ab57a8aee9717e71a936a580fa8572d450fb00339a6f6704b717df0c149a465bab768c61500cd93b61113ff3e4389167f7b2c8e3c0da2d4765286bee555b0bcb4998f59b14fad03180a17c8b4f69bcd1234f4ae85950137665ac2ba80b55cc9b1aafb454b83771aa755acd2a00e93ddb65e696dbed8bdca69fb5e0c5c2097b9cfe4b" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_SHA512, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "93b6fa99485c116ca6efdd4202ea1cf49f4c6345fae692584413743ce5b65510e8e4690aee9a19ea1ff10d57f22aa3548d839f28a8525a34354e9e58e0f3947e056ce2554e21bf287e220b98db3b551258cd42b495e5d1a3bbc83c9d1a02f2a300ef6d866ea75108e44ebb3e16b47df2f6de28feb2be3874dbbf21599451082d86e9f2f462575a8185c69aa1f1fcb6a363c5d71aeba2103449eaf3845285291148d5f78d1646b8dc95cbcc4082f987d948b0e7d4e80b60595f8a7517584e1643" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_1_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 1536 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "bd429bb7c3b00bbea19ba664c0f8172d1a73c3cfa05e2ed656d570c1590918bb7e372ed25e2cd71395ba0a9b1a30f3ee012ffb0546cab8e3581fe3e23f44ab57a8aee9717e71a936a580fa8572d450fb00339a6f6704b717df0c149a465bab768c61500cd93b61113ff3e4389167f7b2c8e3c0da2d4765286bee555b0bcb4998f59b14fad03180a17c8b4f69bcd1234f4ae85950137665ac2ba80b55cc9b1aafb454b83771aa755acd2a00e93ddb65e696dbed8bdca69fb5e0c5c2097b9cfe4b" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "93b6fa99485c116ca6efdd4202ea1cf49f4c6345fae692584413743ce5b65510e8e4690aee9a19ea1ff10d57f22aa3548d839f28a8525a34354e9e58e0f3947e056ce2554e21bf287e220b98db3b551258cd42b495e5d1a3bbc83c9d1a02f2a300ef6d866ea75108e44ebb3e16b47df2f6de28feb2be3874dbbf21599451082d86e9f2f462575a8185c69aa1f1fcb6a363c5d71aeba2103449eaf3845285291148d5f78d1646b8dc95cbcc4082f987d948b0e7d4e80b60595f8a7517584e1643" );
        
            switch( SIG_RSA_SHA512 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA512, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_2_sha256_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_SHA256, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "5aee2b9dbc02a6a2d87ff64a64165dc0b9ce70c79bab2d287939e2601c3223e0493988d5468731ae4edc7d5f5d449335c204fdb0e192c1915c9d694d3a61c3be14df79c4b34d6ac73707829024d263c94f9107fa93f3783de3965522336e18d1e01a142b5103451bb97839eaf2f44703a63050a36b78aef4072ea1a8daaaf1a2918fc03ee957a9c09efdc7287bcb4d6aec4723290294b249b3e3dc63157b560ad9c867323a73ebeb360cc9e482111643b0d86c4e33dcf170155590f0eba7d170789e84de336b7fe2f6cf485ddca94607a4ff379fc49d375c730249dd1a210e7dccd762d1c23c7532e769c6aa88e38e8654ff90f7b34df4c07ba90e89099ec1ed" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_2_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "5aee2b9dbc02a6a2d87ff64a64165dc0b9ce70c79bab2d287939e2601c3223e0493988d5468731ae4edc7d5f5d449335c204fdb0e192c1915c9d694d3a61c3be14df79c4b34d6ac73707829024d263c94f9107fa93f3783de3965522336e18d1e01a142b5103451bb97839eaf2f44703a63050a36b78aef4072ea1a8daaaf1a2918fc03ee957a9c09efdc7287bcb4d6aec4723290294b249b3e3dc63157b560ad9c867323a73ebeb360cc9e482111643b0d86c4e33dcf170155590f0eba7d170789e84de336b7fe2f6cf485ddca94607a4ff379fc49d375c730249dd1a210e7dccd762d1c23c7532e769c6aa88e38e8654ff90f7b34df4c07ba90e89099ec1ed" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_2_verify_fail)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "5aee2b9dbc02a6a2d87ff64a64165dc0b9ce70c79bab2d287939e2601c3223e0493988d5468731ae4edc7d5f5d449335c204fdb0e192c1915c9d694d3a61c3be14df79c4b34d6ac73707829024d263c94f9107fa93f3783de3965522336e18d1e01a142b5103451bb97839eaf2f44703a63050a36b78aef4072ea1a8daaaf1a2918fc03ee957a9c09efdc6287bcb4d6aec4723290294b249b3e3dc63157b560ad9c867323a73ebeb360cc9e482111643b0d86c4e33dcf170155590f0eba7d170789e84de336b7fe2f6cf485ddca94607a4ff379fc49d375c730249dd1a210e7dccd763d1c23c7532e769c6aa88e38e8654ff90f7b34df4c07ba90e89099ec1ed" );
        
            switch( SIG_RSA_SHA256 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA256, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_3_sha224_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_SHA224, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "9d768b8b31421f9d9ced890aafaf8b3468656419049ed268f6e1992066f45dc3e4cd349e8c5ed5a06e4ef5badaba064ba94907dfedf3d708becaf44ae9b27c3866d329311ba93e8ddc7fc284fba05d1bb84fb1e060a5b76b7fa515cfcd2c8144474623672703cac1e15ff4fdf8ef19d365c51ba86e60f4cbbcd07f956060625751bfbecc47945646459cadaddd900603a8149a93b31a6d432e1da1a67eb765f5b2f0bd1adb9af12d731c7b02931b42dbbfd8c7cecde76b817e96f664147a2c5091c6ce4dc562c5f57159d6f9dc9ba2daa212db56677839621bd4805dde62955fb2d0cc2c448109d10ecc6206ea81f0a02e1646471358f3ec146cd3c75f2d390b" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_3_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "9d768b8b31421f9d9ced890aafaf8b3468656419049ed268f6e1992066f45dc3e4cd349e8c5ed5a06e4ef5badaba064ba94907dfedf3d708becaf44ae9b27c3866d329311ba93e8ddc7fc284fba05d1bb84fb1e060a5b76b7fa515cfcd2c8144474623672703cac1e15ff4fdf8ef19d365c51ba86e60f4cbbcd07f956060625751bfbecc47945646459cadaddd900603a8149a93b31a6d432e1da1a67eb765f5b2f0bd1adb9af12d731c7b02931b42dbbfd8c7cecde76b817e96f664147a2c5091c6ce4dc562c5f57159d6f9dc9ba2daa212db56677839621bd4805dde62955fb2d0cc2c448109d10ecc6206ea81f0a02e1646471358f3ec146cd3c75f2d390b" );
        
            switch( SIG_RSA_SHA224 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA224, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_4_sha384_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_SHA384, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "40dcc96822e5612eb33f1dca247a35109ba3845c7a3d556a60e656624bf1c103d94686ca7379e9e329ccd1b19b52bfd48b608df9f59a96a82d3feb0101096dbcb80e46da543b4c982ac6bb1717f24f9fe3f76b7154492b47525be1ddcaf4631d33481531be8f3e685837b40bdf4a02827d79f6a32374147174680f51c8e0d8eed9d5c445a563a7bce9ef4236e7cfdc12b2223ef457c3e8ccc6dd65cc23e977a1f03f5ef584feb9af00efc71a701f9d413b0290af17692cb821a1e863d5778e174b1130659f30583f434f09cb1212471a41dd65c102de64a194b6ae3e43cd75928049db78042c58e980aff3ea2774e42845bcf217410a118cf5deeaa64224dbc8" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_4_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "40dcc96822e5612eb33f1dca247a35109ba3845c7a3d556a60e656624bf1c103d94686ca7379e9e329ccd1b19b52bfd48b608df9f59a96a82d3feb0101096dbcb80e46da543b4c982ac6bb1717f24f9fe3f76b7154492b47525be1ddcaf4631d33481531be8f3e685837b40bdf4a02827d79f6a32374147174680f51c8e0d8eed9d5c445a563a7bce9ef4236e7cfdc12b2223ef457c3e8ccc6dd65cc23e977a1f03f5ef584feb9af00efc71a701f9d413b0290af17692cb821a1e863d5778e174b1130659f30583f434f09cb1212471a41dd65c102de64a194b6ae3e43cd75928049db78042c58e980aff3ea2774e42845bcf217410a118cf5deeaa64224dbc8" );
        
            switch( SIG_RSA_SHA384 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_SHA384, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_5_md2_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_MD2 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_MD2, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "6cbb0e4019d64dd5cd2d48fa43446e5cba1a7edbb79d91b199be75c7d3e7ae0820c44d3a120cd2910f73cbb315e15963a60ea7da3452015d9d6beb5ac998fddbd1fa3e5908abc9151f3ffb70365aaee6fb0cd440d3f5591868fc136fae38ac7bcdb3bde3c6a0362dd8b814f7edadd4a51b2edf2227a40d1e34c29f608add7746731425858eb93661c633b7a90942fca3cd594ab4ec170052d44105643518020782e76235def34d014135bad8daed590200482325c3416c3d66417e80d9f9c6322a54683638247b577445ecd0be2765ce96c4ee45213204026dfba24d5ee89e1ea75538ba39f7149a5ac0fc12d7c53cbc12481d4a8e2d410ec633d800ad4b4304" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(rsa_pkcs1_sign_5_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "6cbb0e4019d64dd5cd2d48fa43446e5cba1a7edbb79d91b199be75c7d3e7ae0820c44d3a120cd2910f73cbb315e15963a60ea7da3452015d9d6beb5ac998fddbd1fa3e5908abc9151f3ffb70365aaee6fb0cd440d3f5591868fc136fae38ac7bcdb3bde3c6a0362dd8b814f7edadd4a51b2edf2227a40d1e34c29f608add7746731425858eb93661c633b7a90942fca3cd594ab4ec170052d44105643518020782e76235def34d014135bad8daed590200482325c3416c3d66417e80d9f9c6322a54683638247b577445ecd0be2765ce96c4ee45213204026dfba24d5ee89e1ea75538ba39f7149a5ac0fc12d7c53cbc12481d4a8e2d410ec633d800ad4b4304" );
        
            switch( SIG_RSA_MD2 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_MD2, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_6_md4_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_MD4 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_MD4, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "b0e60dc4dfaf0f636a3a4414eae2d7bce7c3ce505a46e38f3f654d8769b31b7891ba18f89672fce204bbac6e3764355e65447c087994731cd44f086710e79e8c3ebc6e2cb61edc5d3e05848ab733d95efe2d0252a691e810c17fa57fd2dd296374c9ba17fea704685677f45d668a386c8ca433fbbb56d3bbfb43a489ed9518b1c9ab13ce497a1cec91467453bfe533145a31a095c2de541255141768ccc6fdff3fc790b5050f1122c93c3044a9346947e1b23e8125bf7edbf38c64a4286dfc1b829e983db3117959a2559a8ef97687ab673e231be213d88edc632637b58cdb2d69c51fbf6bf894cff319216718b1e696f75cd4366f53dc2e28b2a00017984207" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(rsa_pkcs1_sign_6_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "b0e60dc4dfaf0f636a3a4414eae2d7bce7c3ce505a46e38f3f654d8769b31b7891ba18f89672fce204bbac6e3764355e65447c087994731cd44f086710e79e8c3ebc6e2cb61edc5d3e05848ab733d95efe2d0252a691e810c17fa57fd2dd296374c9ba17fea704685677f45d668a386c8ca433fbbb56d3bbfb43a489ed9518b1c9ab13ce497a1cec91467453bfe533145a31a095c2de541255141768ccc6fdff3fc790b5050f1122c93c3044a9346947e1b23e8125bf7edbf38c64a4286dfc1b829e983db3117959a2559a8ef97687ab673e231be213d88edc632637b58cdb2d69c51fbf6bf894cff319216718b1e696f75cd4366f53dc2e28b2a00017984207" );
        
            switch( SIG_RSA_MD4 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_MD4, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(rsa_pkcs1_sign_7_md5_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_MD5 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_MD5, 0, hash_result, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(rsa_pkcs1_sign_7_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" );
        
            switch( SIG_RSA_MD5 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_MD5, 0, hash_result, result_str ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */


        FCT_TEST_BGN(rsa_pkcs1_sign_8_raw_2048_bits_rsa)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int hash_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            hash_len = unhexify( hash_result, "1234567890deadbeef" );
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_RAW, hash_len, hash_result, output ) == 0 );
        
            hexify( output_str, output, ctx.len );
        
            fct_chk( strcasecmp( (char *) output_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" ) == 0 );
        
            /* For PKCS#1 v1.5, there is an alternative way to generate signatures */
            if( RSA_PKCS_V15 == RSA_PKCS_V15 )
            {
                memset( output, 0x00, 1000 );
                memset( output_str, 0x00, 1000 );
        
                fct_chk( rsa_rsaes_pkcs1_v15_encrypt( &ctx,
                            &rnd_pseudo_rand, &rnd_info, RSA_PRIVATE,
                            hash_len, hash_result, output ) == 0 );
        
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_8_verify)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            unsigned char output[1000];
            rsa_context ctx;
            size_t hash_len, olen;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
            memset( output, 0x00, sizeof( output ) );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            hash_len = unhexify( hash_result, "1234567890deadbeef" );
            unhexify( result_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" );
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_RAW, hash_len, hash_result, result_str ) == 0 );
        
            /* For PKCS#1 v1.5, there is an alternative way to verify signatures */
            if( RSA_PKCS_V15 == RSA_PKCS_V15 )
            {
                int ok;
        
                fct_chk( rsa_rsaes_pkcs1_v15_decrypt( &ctx,
                            NULL, NULL, RSA_PUBLIC,
                            &olen, result_str, output, sizeof( output ) ) == 0 );
        
                ok = olen == hash_len && memcmp( output, hash_result, olen ) == 0;
                if( 0 == 0 )
                    fct_chk( ok == 1 );
                else
                    fct_chk( ok == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_8_verify_wrong_raw_hash)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            unsigned char output[1000];
            rsa_context ctx;
            size_t hash_len, olen;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
            memset( output, 0x00, sizeof( output ) );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            hash_len = unhexify( hash_result, "1234567890deadcafe" );
            unhexify( result_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" );
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_RAW, hash_len, hash_result, result_str ) == POLARSSL_ERR_RSA_VERIFY_FAILED );
        
            /* For PKCS#1 v1.5, there is an alternative way to verify signatures */
            if( RSA_PKCS_V15 == RSA_PKCS_V15 )
            {
                int ok;
        
                fct_chk( rsa_rsaes_pkcs1_v15_decrypt( &ctx,
                            NULL, NULL, RSA_PUBLIC,
                            &olen, result_str, output, sizeof( output ) ) == 0 );
        
                ok = olen == hash_len && memcmp( output, hash_result, olen ) == 0;
                if( POLARSSL_ERR_RSA_VERIFY_FAILED == 0 )
                    fct_chk( ok == 1 );
                else
                    fct_chk( ok == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_9_invalid_digest_type)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( 1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, 1, 0, hash_result, output ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_9_verify_invalid_digest_type)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" );
        
            switch( 1 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, 1, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_8_invalid_padding_type)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            int msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, 2, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            switch( SIG_RSA_MD5 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_sign( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, SIG_RSA_MD5, 0, hash_result, output ) == POLARSSL_ERR_RSA_INVALID_PADDING );
            if( POLARSSL_ERR_RSA_INVALID_PADDING == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_sign_8_verify_invalid_padding_type)
        {
            unsigned char message_str[1000];
            unsigned char hash_result[1000];
            unsigned char result_str[1000];
            rsa_context ctx;
            int msg_len;
        
            rsa_init( &ctx, 1, 0 );
            memset( message_str, 0x00, 1000 );
            memset( hash_result, 0x00, 1000 );
            memset( result_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
            unhexify( result_str, "3bcf673c3b27f6e2ece4bb97c7a37161e6c6ee7419ef366efc3cfee0f15f415ff6d9d4390937386c6fec1771acba73f24ec6b0469ea8b88083f0b4e1b6069d7bf286e67cf94182a548663137e82a6e09c35de2c27779da0503f1f5bedfebadf2a875f17763a0564df4a6d945a5a3e46bc90fb692af3a55106aafc6b577587456ff8d49cfd5c299d7a2b776dbe4c1ae777b0f64aa3bab27689af32d6cc76157c7dc6900a3469e18a7d9b6bfe4951d1105a08864575e4f4ec05b3e053f9b7a2d5653ae085e50a63380d6bdd6f58ab378d7e0a2be708c559849891317089ab04c82d8bc589ea088b90b11dea5cf85856ff7e609cc1adb1d403beead4c126ff29021" );
        
            switch( SIG_RSA_MD5 )
            {
        #ifdef POLARSSL_MD2_C
            case SIG_RSA_MD2:
                md2( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD4_C
            case SIG_RSA_MD4:
                md4( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_MD5_C
            case SIG_RSA_MD5:
                md5( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA1_C
            case SIG_RSA_SHA1:
                sha1( message_str, msg_len, hash_result );
                break;
        #endif
        #ifdef POLARSSL_SHA2_C
            case SIG_RSA_SHA224:
                sha2( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA256:
                sha2( message_str, msg_len, hash_result, 0 );
                break;
        #endif
        #ifdef POLARSSL_SHA4_C
            case SIG_RSA_SHA384:
                sha4( message_str, msg_len, hash_result, 1 );
                break;
            case SIG_RSA_SHA512:
                sha4( message_str, msg_len, hash_result, 0 );
                break;
        #endif
            default:
                ; /* do nothing */
            }
        
            fct_chk( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, SIG_RSA_MD5, 0, hash_result, result_str ) == POLARSSL_ERR_RSA_INVALID_PADDING );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_encrypt_1)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            size_t msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4E636AF98E40F3ADCFCCB698F4E80B9F" );
        
            fct_chk( rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info, RSA_PUBLIC, msg_len, message_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "b0c0b193ba4a5b4502bfacd1a9c2697da5510f3e3ab7274cf404418afd2c62c89b98d83bbc21c8c1bf1afe6d8bf40425e053e9c03e03a3be0edbe1eda073fade1cc286cc0305a493d98fe795634c3cad7feb513edb742d66d910c87d07f6b0055c3488bb262b5fd1ce8747af64801fb39d2d3a3e57086ffe55ab8d0a2ca86975629a0f85767a4990c532a7c2dab1647997ebb234d0b28a0008bfebfc905e7ba5b30b60566a5e0190417465efdbf549934b8f0c5c9f36b7c5b6373a47ae553ced0608a161b1b70dfa509375cf7a3598223a6d7b7a1d1a06ac74d345a9bb7c0e44c8388858a4f1d8115f2bd769ffa69020385fa286302c80e950f9e2751308666c" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_decrypt_1_verify)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            size_t output_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" );
            output_len = 0;
        
            fct_chk( rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, &output_len, message_str, output, 1000 ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strncasecmp( (char *) output_str, "4E636AF98E40F3ADCFCCB698F4E80B9F", strlen( "4E636AF98E40F3ADCFCCB698F4E80B9F" ) ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_encrypt_2_data_too_large)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            size_t msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" );
        
            fct_chk( rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info, RSA_PUBLIC, msg_len, message_str, output ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_decrypt_2_data_too_small)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            size_t output_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "deadbeafcafedeadbeeffedcba9876" );
            output_len = 0;
        
            fct_chk( rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, &output_len, message_str, output, 1000 ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strncasecmp( (char *) output_str, "4E636AF98E40F3ADCFCCB698F4E80B9F", strlen( "4E636AF98E40F3ADCFCCB698F4E80B9F" ) ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_encrypt_3_invalid_padding_mode)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            size_t msg_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            rsa_init( &ctx, 2, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4E636AF98E40F3ADCFCCB698F4E80B9F" );
        
            fct_chk( rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info, RSA_PUBLIC, msg_len, message_str, output ) == POLARSSL_ERR_RSA_INVALID_PADDING );
            if( POLARSSL_ERR_RSA_INVALID_PADDING == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_decrypt_3_invalid_padding_mode)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            size_t output_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, 2, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" );
            output_len = 0;
        
            fct_chk( rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, &output_len, message_str, output, 1000 ) == POLARSSL_ERR_RSA_INVALID_PADDING );
            if( POLARSSL_ERR_RSA_INVALID_PADDING == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strncasecmp( (char *) output_str, "4E636AF98E40F3ADCFCCB698F4E80B9F", strlen( "4E636AF98E40F3ADCFCCB698F4E80B9F" ) ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_pkcs1_decrypt_4_output_buffer_too_small)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            size_t output_len;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" );
            output_len = 0;
        
            fct_chk( rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, &output_len, message_str, output, 15 ) == POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );
            if( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strncasecmp( (char *) output_str, "4E636AF98E40F3ADCFCCB698F4E80B9F", strlen( "4E636AF98E40F3ADCFCCB698F4E80B9F" ) ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_empty_private_key)
        {
            rsa_context ctx;
            memset( &ctx, 0x00, sizeof( rsa_context ) );
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_1_correct)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_2_no_p)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_3_no_q)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_4_no_n)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_5_no_e)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_6_no_d)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_7_no_dp)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_8_no_dq)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_9_no_qp)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCB" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_private_key_10_incorrect)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            ctx.len = 2048 / 8;
            if( strlen( "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) )
            {
                fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            }
            if( strlen( "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) )
            {
                fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            }
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
            if( strlen( "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCC" ) )
            {
                fct_chk( mpi_read_string( &ctx.D, 16, "77B1D99300D6A54E864962DA09AE10CF19A7FB888456BC2672B72AEA52B204914493D16C184AD201EC3F762E1FBD8702BA796EF953D9EA2F26300D285264F11B0C8301D0207FEB1E2C984445C899B0ACEBAA74EF014DD1D4BDDB43202C08D2FF9692D8D788478DEC829EB52AFB5AE068FBDBAC499A27FACECC391E75C936D55F07BB45EE184DAB45808E15722502F279F89B38C1CB292557E5063597F52C75D61001EDC33F4739353E33E56AD273B067C1A2760208529EA421774A5FFFCB3423B1E0051E7702A55D80CBF2141569F18F87BFF538A1DA8EDBB2693A539F68E0D62D77743F89EACF3B1723BDB25CE2F333FA63CACF0E67DF1A431893BB9B352FCC" ) == 0 );
            }
            if( strlen( "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) )
            {
                fct_chk( mpi_read_string( &ctx.DP, 16, "9A66CF76572A71A17475794FA1C8C70D987E581E990D772BB27C77C53FF1ECBB31260E9EDAFAEBC79991807E48918EAB8C3A5F03A600F30C69511546AE788EDF53168E2D035D300EDCD5E4BF3AA2A6D603EA0A7BD11E1C1089657306DF8A64E7F1BC6B266B825C1A6C5F0FC85775F4CF7ACD63367E42EAFE46511D58AD6DFE0F" ) == 0 );
            }
            if( strlen( "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) )
            {
                fct_chk( mpi_read_string( &ctx.DQ, 16, "844DBDD20925D9164F9A1E2F707076C261CCA8337D0241392B38AE3C12342F3AC14F8FD6DF4A1C36839662BD0D227344CD55A32AE5DBD2309A9A2B8A2C82BE6DDDDCE81D1B694775D9047AA765CA0C6E1BB8E61C8B7BE27ED711E8EE2FEAD87F3491F76A6D2262C14189EACDFD4CEFE0BF9D0A5B49857E0ED22CBEB98DC8D45B" ) == 0 );
            }
            if( strlen( "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) )
            {
                fct_chk( mpi_read_string( &ctx.QP, 16, "4951A7B174DF972C37BADCC38457B5EDD1F078BC613E75CE25E08814E12461C7A1C189A70EB8138294298D141244C7A9DE31AB4F6D38B40B04D6353CD30F77ADBF66BBDE41C7BE463C5E30AAA3F7BAD6CEE99506DEAAFA2F335C1B1C5C88B8ABB0D0387EE0D1B4E7027F7F085A025CEDB5CCE18B88C0462F1C3C910D47C0D4AB" ) == 0 );
            }
        
            fct_chk( rsa_check_privkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_1_correct)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_2_even_n)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a20340" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a20340" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_3_even_e)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a20340" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a20340" ) == 0 );
            }
            if( strlen( "65536" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "65536" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_4_n_exactly_128_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "fedcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "fedcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_5_n_smaller_than_128_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "7edcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "7edcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_6_n_exactly_4096_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_7_n_larger_than_4096_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "01b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "01b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_8_e_exactly_2_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "fedcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "fedcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "3" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_8_e_exactly_1_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "fedcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "fedcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "1" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "1" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_8_e_exactly_64_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "fedcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "fedcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "00fedcba9876543213" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "00fedcba9876543213" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_8_e_larger_than_64_bits)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "fedcba9876543210deadbeefcafe4321" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "fedcba9876543210deadbeefcafe4321" ) == 0 );
            }
            if( strlen( "01fedcba9876543213" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "01fedcba9876543213" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_9_e_has_size_n_2)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034d" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034d" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_check_public_key_10_e_has_size_n)
        {
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            if( strlen( "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.N, 16, "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
            if( strlen( "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) )
            {
                fct_chk( mpi_read_string( &ctx.E, 16, "00b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034fb38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            }
        
            fct_chk( rsa_check_pubkey( &ctx ) == POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_private_correct)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            fct_chk( rsa_private( &ctx, rnd_pseudo_rand, &rnd_info, message_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "48ce62658d82be10737bd5d3579aed15bc82617e6758ba862eeb12d049d7bacaf2f62fce8bf6e980763d1951f7f0eae3a493df9890d249314b39d00d6ef791de0daebf2c50f46e54aeb63a89113defe85de6dbe77642aae9f2eceb420f3a47a56355396e728917f17876bb829fabcaeef8bf7ef6de2ff9e84e6108ea2e52bbb62b7b288efa0a3835175b8b08fac56f7396eceb1c692d419ecb79d80aef5bc08a75d89de9f2b2d411d881c0e3ffad24c311a19029d210d3d3534f1b626f982ea322b4d1cfba476860ef20d4f672f38c371084b5301b429b747ea051a619e4430e0dac33c12f9ee41ca4d81a4f6da3e495aa8524574bdc60d290dd1f7a62e90a67" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_private_data_larger_than_n)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            mpi P1, Q1, H, G;
            rnd_pseudo_info rnd_info;
        
            memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );
        
            mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
        
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.P, 16, "e79a373182bfaa722eb035f772ad2a9464bd842de59432c18bbab3a7dfeae318c9b915ee487861ab665a40bd6cda560152578e8579016c929df99fea05b4d64efca1d543850bc8164b40d71ed7f3fa4105df0fb9b9ad2a18ce182c8a4f4f975bea9aa0b9a1438a27a28e97ac8330ef37383414d1bd64607d6979ac050424fd17" ) == 0 );
            fct_chk( mpi_read_string( &ctx.Q, 16, "c6749cbb0db8c5a177672d4728a8b22392b2fc4d3b8361d5c0d5055a1b4e46d821f757c24eef2a51c561941b93b3ace7340074c058c9bb48e7e7414f42c41da4cccb5c2ba91deb30c586b7fb18af12a52995592ad139d3be429add6547e044becedaf31fa3b39421e24ee034fbf367d11f6b8f88ee483d163b431e1654ad3e89" ) == 0 );
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
            fct_chk( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
            fct_chk( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
            fct_chk( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
            fct_chk( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
            fct_chk( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );
        
            fct_chk( rsa_check_privkey( &ctx ) == 0 );
        
            unhexify( message_str, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" );
        
            fct_chk( rsa_private( &ctx, rnd_pseudo_rand, &rnd_info, message_str, output ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" ) == 0 );
            }
        
            mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_public_correct)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            unhexify( message_str, "59779fd2a39e56640c4fc1e67b60aeffcecd78aed7ad2bdfa464e93d04198d48466b8da7445f25bfa19db2844edd5c8f539cf772cc132b483169d390db28a43bc4ee0f038f6568ffc87447746cb72fefac2d6d90ee3143a915ac4688028805905a68eb8f8a96674b093c495eddd8704461eaa2b345efbb2ad6930acd8023f870" );
        
            fct_chk( rsa_public( &ctx, message_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "1f5e927c13ff231090b0f18c8c3526428ed0f4a7561457ee5afe4d22d5d9220c34ef5b9a34d0c07f7248a1f3d57f95d10f7936b3063e40660b3a7ca3e73608b013f85a6e778ac7c60d576e9d9c0c5a79ad84ceea74e4722eb3553bdb0c2d7783dac050520cb27ca73478b509873cb0dcbd1d51dd8fccb96c29ad314f36d67cc57835d92d94defa0399feb095fd41b9f0b2be10f6041079ed4290040449f8a79aba50b0a1f8cf83c9fb8772b0686ec1b29cb1814bb06f9c024857db54d395a8da9a2c6f9f53b94bec612a0cb306a3eaa9fc80992e85d9d232e37a50cabe48c9343f039601ff7d95d60025e582aec475d031888310e8ec3833b394a5cf0599101e" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(rsa_public_data_larger_than_n)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            unhexify( message_str, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" );
        
            fct_chk( rsa_public( &ctx, message_str, output ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "605baf947c0de49e4f6a0dfb94a43ae318d5df8ed20ba4ba5a37a73fb009c5c9e5cce8b70a25b1c7580f389f0d7092485cdfa02208b70d33482edf07a7eafebdc54862ca0e0396a5a7d09991b9753eb1ffb6091971bb5789c6b121abbcd0a3cbaa39969fa7c28146fce96c6d03272e3793e5be8f5abfa9afcbebb986d7b3050604a2af4d3a40fa6c003781a539a60259d1e84f13322da9e538a49c369b83e7286bf7d30b64bbb773506705da5d5d5483a563a1ffacc902fb75c9a751b1e83cdc7a6db0470056883f48b5a5446b43b1d180ea12ba11a6a8d93b3b32a30156b6084b7fb142998a2a0d28014b84098ece7d9d5e4d55cc342ca26f5a0167a679dec8" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();

#ifdef POLARSSL_ENTROPY_C
#ifdef POLARSSL_CTR_DRBG_C

        FCT_TEST_BGN(rsa_generate_key)
        {
            rsa_context ctx;
            entropy_context entropy;
            ctr_drbg_context ctr_drbg;
            const char *pers = "test_suite_rsa";
        
            entropy_init( &entropy );
            fct_chk( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                                        (const unsigned char *) pers, strlen( pers ) ) == 0 );
        
            rsa_init( &ctx, 0, 0 );
        
            fct_chk( rsa_gen_key( &ctx, ctr_drbg_random, &ctr_drbg, 128, 3 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( rsa_check_privkey( &ctx ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ENTROPY_C */
#endif /* POLARSSL_CTR_DRBG_C */

#ifdef POLARSSL_ENTROPY_C
#ifdef POLARSSL_CTR_DRBG_C

        FCT_TEST_BGN(rsa_generate_key_number_of_bits_too_small)
        {
            rsa_context ctx;
            entropy_context entropy;
            ctr_drbg_context ctr_drbg;
            const char *pers = "test_suite_rsa";
        
            entropy_init( &entropy );
            fct_chk( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                                        (const unsigned char *) pers, strlen( pers ) ) == 0 );
        
            rsa_init( &ctx, 0, 0 );
        
            fct_chk( rsa_gen_key( &ctx, ctr_drbg_random, &ctr_drbg, 127, 3 ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                fct_chk( rsa_check_privkey( &ctx ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ENTROPY_C */
#endif /* POLARSSL_CTR_DRBG_C */

#ifdef POLARSSL_ENTROPY_C
#ifdef POLARSSL_CTR_DRBG_C

        FCT_TEST_BGN(rsa_generate_key_exponent_too_small)
        {
            rsa_context ctx;
            entropy_context entropy;
            ctr_drbg_context ctr_drbg;
            const char *pers = "test_suite_rsa";
        
            entropy_init( &entropy );
            fct_chk( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                                        (const unsigned char *) pers, strlen( pers ) ) == 0 );
        
            rsa_init( &ctx, 0, 0 );
        
            fct_chk( rsa_gen_key( &ctx, ctr_drbg_random, &ctr_drbg, 128, 2 ) == POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            if( POLARSSL_ERR_RSA_BAD_INPUT_DATA == 0 )
            {
                fct_chk( rsa_check_privkey( &ctx ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ENTROPY_C */
#endif /* POLARSSL_CTR_DRBG_C */

#ifdef POLARSSL_ENTROPY_C
#ifdef POLARSSL_CTR_DRBG_C

        FCT_TEST_BGN(rsa_generate_key)
        {
            rsa_context ctx;
            entropy_context entropy;
            ctr_drbg_context ctr_drbg;
            const char *pers = "test_suite_rsa";
        
            entropy_init( &entropy );
            fct_chk( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                                        (const unsigned char *) pers, strlen( pers ) ) == 0 );
        
            rsa_init( &ctx, 0, 0 );
        
            fct_chk( rsa_gen_key( &ctx, ctr_drbg_random, &ctr_drbg, 1024, 3 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( rsa_check_privkey( &ctx ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ENTROPY_C */
#endif /* POLARSSL_CTR_DRBG_C */


        FCT_TEST_BGN(rsa_pkcs1_encrypt_bad_rng)
        {
            unsigned char message_str[1000];
            unsigned char output[1000];
            unsigned char output_str[1000];
            rsa_context ctx;
            size_t msg_len;
        
            rsa_init( &ctx, RSA_PKCS_V15, 0 );
            memset( message_str, 0x00, 1000 );
            memset( output, 0x00, 1000 );
            memset( output_str, 0x00, 1000 );
        
            ctx.len = 2048 / 8;
            fct_chk( mpi_read_string( &ctx.N, 16, "b38ac65c8141f7f5c96e14470e851936a67bf94cc6821a39ac12c05f7c0b06d9e6ddba2224703b02e25f31452f9c4a8417b62675fdc6df46b94813bc7b9769a892c482b830bfe0ad42e46668ace68903617faf6681f4babf1cc8e4b0420d3c7f61dc45434c6b54e2c3ee0fc07908509d79c9826e673bf8363255adb0add2401039a7bcd1b4ecf0fbe6ec8369d2da486eec59559dd1d54c9b24190965eafbdab203b35255765261cd0909acf93c3b8b8428cbb448de4715d1b813d0c94829c229543d391ce0adab5351f97a3810c1f73d7b1458b97daed4209c50e16d064d2d5bfda8c23893d755222793146d0a78c3d64f35549141486c3b0961a7b4c1a2034f" ) == 0 );
            fct_chk( mpi_read_string( &ctx.E, 16, "3" ) == 0 );
        
            fct_chk( rsa_check_pubkey( &ctx ) == 0 );
        
            msg_len = unhexify( message_str, "4E636AF98E40F3ADCFCCB698F4E80B9F" );
        
            fct_chk( rsa_pkcs1_encrypt( &ctx, &rnd_zero_rand, NULL, RSA_PUBLIC, msg_len, message_str, output ) == POLARSSL_ERR_RSA_RNG_FAILED );
            if( POLARSSL_ERR_RSA_RNG_FAILED == 0 )
            {
                hexify( output_str, output, ctx.len );
        
                fct_chk( strcasecmp( (char *) output_str, "a42eda41e56235e666e7faaa77100197f657288a1bf183e4820f0c37ce2c456b960278d6003e0bbcd4be4a969f8e8fd9231e1f492414f00ed09844994c86ec32db7cde3bec7f0c3dbf6ae55baeb2712fa609f5fc3207a824eb3dace31849cd6a6084318523912bccb84cf42e3c6d6d1685131d69bb545acec827d2b0dfdd5568b7dcc4f5a11d6916583fefa689d367f8c9e1d95dcd2240895a9470b0c1730f97cd6e8546860bd254801769f54be96e16362ddcbf34d56035028890199e0f48db38642cb66a4181e028a6443a404fea284ce02b4614b683367d40874e505611d23142d49f06feea831d52d347b13610b413c4efc43a6de9f0b08d2a951dc503b6" ) == 0 );
            }
        
            rsa_free( &ctx );
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(rsa_selftest)
        {
            fct_chk( rsa_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_RSA_C */
#endif /* POLARSSL_BIGNUM_C */
#endif /* POLARSSL_GENPRIME */

}
FCT_END();

