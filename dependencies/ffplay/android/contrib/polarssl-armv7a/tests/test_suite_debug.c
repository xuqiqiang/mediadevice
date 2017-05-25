#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/debug.h>

struct buffer_data
{
    char buf[2000];
    char *ptr;
};

void string_debug(void *data, int level, const char *str)
{
    struct buffer_data *buffer = (struct buffer_data *) data;
    ((void) level);

    memcpy(buffer->ptr, str, strlen(str));
    buffer->ptr += strlen(str);
}

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
#ifdef POLARSSL_DEBUG_C
#ifdef POLARSSL_BIGNUM_C
#ifdef POLARSSL_SSL_TLS_C
#ifdef POLARSSL_RSA_C


    FCT_SUITE_BGN(test_suite_debug)
    {
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_BASE64_C

        FCT_TEST_BGN(debug_print_certificate_1)
        {
            x509_cert   crt;
            ssl_context ssl;
            struct buffer_data buffer;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            debug_print_crt( &ssl, 0, "MyFile", 999, "PREFIX_", &crt);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): PREFIX_ #1:\nMyFile(0999): cert. version : 3\nMyFile(0999): serial number : 01\nMyFile(0999): issuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nMyFile(0999): subject name  : C=NL, O=PolarSSL, CN=PolarSSL Server 1\nMyFile(0999): issued  on    : 2011-02-12 14:44:06\nMyFile(0999): expires on    : 2021-02-12 14:44:06\nMyFile(0999): signed using  : RSA+SHA1\nMyFile(0999): RSA key size  : 2048 bits\nMyFile(0999): value of 'crt->rsa.N' (2048 bits) is:\nMyFile(0999):  a9 02 1f 3d 40 6a d5 55 53 8b fd 36 ee 82 65 2e\nMyFile(0999):  15 61 5e 89 bf b8 e8 45 90 db ee 88 16 52 d3 f1\nMyFile(0999):  43 50 47 96 12 59 64 87 6b fd 2b e0 46 f9 73 be\nMyFile(0999):  dd cf 92 e1 91 5b ed 66 a0 6f 89 29 79 45 80 d0\nMyFile(0999):  83 6a d5 41 43 77 5f 39 7c 09 04 47 82 b0 57 39\nMyFile(0999):  70 ed a3 ec 15 19 1e a8 33 08 47 c1 05 42 a9 fd\nMyFile(0999):  4c c3 b4 df dd 06 1f 4d 10 51 40 67 73 13 0f 40\nMyFile(0999):  f8 6d 81 25 5f 0a b1 53 c6 30 7e 15 39 ac f9 5a\nMyFile(0999):  ee 7f 92 9e a6 05 5b e7 13 97 85 b5 23 92 d9 d4\nMyFile(0999):  24 06 d5 09 25 89 75 07 dd a6 1a 8f 3f 09 19 be\nMyFile(0999):  ad 65 2c 64 eb 95 9b dc fe 41 5e 17 a6 da 6c 5b\nMyFile(0999):  69 cc 02 ba 14 2c 16 24 9c 4a dc cd d0 f7 52 67\nMyFile(0999):  73 f1 2d a0 23 fd 7e f4 31 ca 2d 70 ca 89 0b 04\nMyFile(0999):  db 2e a6 4f 70 6e 9e ce bd 58 89 e2 53 59 9e 6e\nMyFile(0999):  5a 92 65 e2 88 3f 0c 94 19 a3 dd e5 e8 9d 95 13\nMyFile(0999):  ed 29 db ab 70 12 dc 5a ca 6b 17 ab 52 82 54 b1\nMyFile(0999): value of 'crt->rsa.E' (17 bits) is:\nMyFile(0999):  01 00 01\n" ) == 0 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_BASE64_C */


        FCT_TEST_BGN(debug_print_mpi_1)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "01020304050607" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (49 bits) is:\nMyFile(0999):  01 02 03 04 05 06 07\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(debug_print_mpi_2)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "00000000000007" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (3 bits) is:\nMyFile(0999):  07\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(debug_print_mpi_3)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "00000000000000" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (0 bits) is:\nMyFile(0999):  00\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(debug_print_mpi_4)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (764 bits) is:\nMyFile(0999):  09 41 37 9d 00 fe d1 49 1f e1 5d f2 84 df de 4a\nMyFile(0999):  14 2f 68 aa 8d 41 20 23 19 5c ee 66 88 3e 62 90\nMyFile(0999):  ff e7 03 f4 ea 59 63 bf 21 27 13 ce e4 6b 10 7c\nMyFile(0999):  09 18 2b 5e dc d9 55 ad ac 41 8b f4 91 8e 28 89\nMyFile(0999):  af 48 e1 09 9d 51 38 30 ce c8 5c 26 ac 1e 15 8b\nMyFile(0999):  52 62 0e 33 ba 86 92 f8 93 ef bb 2f 95 8b 44 24\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(debug_print_mpi_5)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "0000000000000000000000000000000000000000000000000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (764 bits) is:\nMyFile(0999):  09 41 37 9d 00 fe d1 49 1f e1 5d f2 84 df de 4a\nMyFile(0999):  14 2f 68 aa 8d 41 20 23 19 5c ee 66 88 3e 62 90\nMyFile(0999):  ff e7 03 f4 ea 59 63 bf 21 27 13 ce e4 6b 10 7c\nMyFile(0999):  09 18 2b 5e dc d9 55 ad ac 41 8b f4 91 8e 28 89\nMyFile(0999):  af 48 e1 09 9d 51 38 30 ce c8 5c 26 ac 1e 15 8b\nMyFile(0999):  52 62 0e 33 ba 86 92 f8 93 ef bb 2f 95 8b 44 24\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(debug_print_mpi_6)
        {
            ssl_context ssl;
            struct buffer_data buffer;
            mpi val;
        
            mpi_init( &val );
        
            memset( &ssl, 0, sizeof( ssl_context ) );
            memset( buffer.buf, 0, 2000 );
            buffer.ptr = buffer.buf; 
        
            fct_chk( mpi_read_string( &val, 16, "0000000000000000000000000000000000000000000000000000000041379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" ) == 0 );
            ssl_set_dbg(&ssl, string_debug, &buffer);
        
            debug_print_mpi( &ssl, 0, "MyFile", 999, "VALUE", &val);
        
            fct_chk( strcmp( buffer.buf, "MyFile(0999): value of 'VALUE' (759 bits) is:\nMyFile(0999):  41 37 9d 00 fe d1 49 1f e1 5d f2 84 df de 4a 14\nMyFile(0999):  2f 68 aa 8d 41 20 23 19 5c ee 66 88 3e 62 90 ff\nMyFile(0999):  e7 03 f4 ea 59 63 bf 21 27 13 ce e4 6b 10 7c 09\nMyFile(0999):  18 2b 5e dc d9 55 ad ac 41 8b f4 91 8e 28 89 af\nMyFile(0999):  48 e1 09 9d 51 38 30 ce c8 5c 26 ac 1e 15 8b 52\nMyFile(0999):  62 0e 33 ba 86 92 f8 93 ef bb 2f 95 8b 44 24\n" ) == 0 );
        
            mpi_free( &val );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_DEBUG_C */
#endif /* POLARSSL_BIGNUM_C */
#endif /* POLARSSL_SSL_TLS_C */
#endif /* POLARSSL_RSA_C */

}
FCT_END();

