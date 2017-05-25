#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/x509write.h>
#include <polarssl/x509.h>
#include <polarssl/pem.h>

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
#ifdef POLARSSL_X509_WRITE_C
#ifdef POLARSSL_BIGNUM_C


    FCT_SUITE_BGN(test_suite_x509write)
    {
#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(certificate_request_check_server1_sha1)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_SHA1 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.sha1", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(certificate_request_check_server1_sha224)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_SHA224 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.sha224", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(certificate_request_check_server1_sha256)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_SHA256 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.sha256", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(certificate_request_check_server1_sha384)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_SHA384 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.sha384", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(certificate_request_check_server1_sha512)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_SHA512 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.sha512", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(certificate_request_check_server1_md4)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_MD4 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.md4", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(certificate_request_check_server1_md5)
        {
            rsa_context rsa;
            pem_context pem;
            x509_req_name req_name, *cur;
            unsigned char *c;
            unsigned char buf[4000];
            unsigned char check_buf[4000];
            int ret;
            size_t olen = 2000, r;
            FILE *f;
        
            cur = &req_name;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_CN );
            strcpy( cur->name, "PolarSSL Server 1" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_ORGANIZATION );
            strcpy( cur->name, "PolarSSL" );
            cur->next = malloc( sizeof(x509_req_name) );
            cur = cur->next;
        
            memset( cur, 0, sizeof(x509_req_name) );
            strcpy( cur->oid, OID_COUNTRY );
            strcpy( cur->name, "NL" );
        
            memset( &rsa, 0, sizeof(rsa_context) );
            ret = x509parse_keyfile( &rsa, "data_files/server1.key", NULL );
            fct_chk( ret == 0 );
            if( ret != 0 )
                return 0;
        
            ret = x509_write_cert_req( buf, 4000, &rsa, &req_name, SIG_RSA_MD5 );
            fct_chk( ret >= 0 );
        
            c = buf + 3999 - ret;
        
            f = fopen( "data_files/server1.req.md5", "r" );
            fct_chk( f != NULL );
            r = fread( check_buf, 1, 4000, f );
            fclose( f );
            fct_chk( r != 0 );
        
            pem_init( &pem );
            pem_read_buffer( &pem, (char *) "-----BEGIN CERTIFICATE REQUEST-----", (char *) "-----END CERTIFICATE REQUEST-----", check_buf, NULL, 0, &olen );
        
            fct_chk( memcmp( c, pem.buf, pem.buflen ) == 0 );
            fct_chk( pem.buflen == (size_t) ret );
        
            while( ( cur = req_name.next ) != NULL )
            {
                req_name.next = cur->next;
                free( cur );
            }
        
            rsa_free( &rsa );
            pem_free( &pem );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_X509_WRITE_C */
#endif /* POLARSSL_BIGNUM_C */

}
FCT_END();

