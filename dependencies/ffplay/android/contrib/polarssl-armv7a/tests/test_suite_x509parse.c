#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/x509.h>
#include <polarssl/pem.h>

int verify_none( void *data, x509_cert *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags |= BADCERT_OTHER;
    
    return 0;
}

int verify_all( void *data, x509_cert *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags = 0;

    return 0;
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
#ifdef POLARSSL_X509_PARSE_C
#ifdef POLARSSL_BIGNUM_C


    FCT_SUITE_BGN(test_suite_x509parse)
    {
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_1)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 01\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Server 1\nissued  on    : 2011-02-12 14:44:06\nexpires on    : 2021-02-12 14:44:06\nsigned using  : RSA+SHA1\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_2)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 02\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=localhost\nissued  on    : 2011-02-12 14:44:06\nexpires on    : 2021-02-12 14:44:06\nsigned using  : RSA+SHA1\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_3)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/test-ca.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 00\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nissued  on    : 2011-02-12 14:44:00\nexpires on    : 2021-02-12 14:44:00\nsigned using  : RSA+SHA1\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_md2_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_md2.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 09\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert MD2\nissued  on    : 2009-07-12 10:56:59\nexpires on    : 2011-07-12 10:56:59\nsigned using  : RSA+MD2\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_md4_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_md4.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 05\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert MD4\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+MD4\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_md5_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_md5.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 06\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert MD5\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+MD5\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_sha1_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha1.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 07\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert SHA1\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+SHA1\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_sha224_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha224.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 08\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert SHA224\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+SHA224\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_sha256_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha256.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 09\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert SHA256\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+SHA256\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_sha384_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha384.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 0A\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert SHA384\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+SHA384\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_information_sha512_digest)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha512.crt" ) == 0 );
            res = x509parse_cert_info( buf, 2000, "", &crt );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "cert. version : 3\nserial number : 0B\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nsubject name  : C=NL, O=PolarSSL, CN=PolarSSL Cert SHA512\nissued  on    : 2011-02-12 14:44:07\nexpires on    : 2021-02-12 14:44:07\nsigned using  : RSA+SHA512\nRSA key size  : 2048 bits\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_1)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-20 10:24:19\nnext update   : 2011-02-20 11:24:19\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA1\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_md2_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_md2.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2009-07-19 19:56:37\nnext update   : 2009-09-17 19:56:37\nRevoked certificates:\nserial number: 01 revocation date: 2009-02-09 21:12:36\nserial number: 03 revocation date: 2009-02-09 21:12:36\nsigned using  : RSA+MD2\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_md4_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_md4.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+MD4\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_md5_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_md5.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+MD5\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_sha1_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_sha1.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA1\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_sha224_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_sha224.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA224\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_sha256_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_sha256.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA256\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_sha384_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_sha384.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA384\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_crl_information_sha512_digest)
        {
            x509_crl   crl;
            char buf[2000];
            int res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_sha512.pem" ) == 0 );
            res = x509parse_crl_info( buf, 2000, "", &crl );
        
            x509_crl_free( &crl );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "CRL version   : 1\nissuer name   : C=NL, O=PolarSSL, CN=PolarSSL Test CA\nthis update   : 2011-02-12 14:44:07\nnext update   : 2011-04-13 14:44:07\nRevoked certificates:\nserial number: 01 revocation date: 2011-02-12 14:44:07\nserial number: 03 revocation date: 2011-02-12 14:44:07\nsigned using  : RSA+SHA512\n" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_1_no_password_when_required)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/test-ca.key", NULL );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_REQUIRED );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_2_correct_password)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/test-ca.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_3_wrong_password)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/test-ca.key", "PolarSSLWRONG" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_DES_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_4_des_encrypted)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/keyfile.des", "testkey" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_DES_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_5_3des_encrypted)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/keyfile.3des", "testkey" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_AES_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_6_aes_128_encrypted)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/keyfile.aes128", "testkey" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_AES_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_7_aes_192_encrypted)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/keyfile.aes192", "testkey" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_AES_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_8_aes_256_encrypted)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/keyfile.aes256", "testkey" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_AES_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_key_9_pkcs8_wrapped)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/format_gen.key", "" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_10_pkcs8_encrypted_sha1_3des)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_3des.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_101_pkcs8_encrypted_sha1_3des_wrong_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_3des.key", "PolarSSLTes" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_102_pkcs8_encrypted_sha1_3des_no_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_3des.key", "" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_REQUIRED );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_11_pkcs8_encrypted_sha1_3des_der)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_3des.der", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_12_pkcs8_encrypted_sha1_2des)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_2des.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_121_pkcs8_encrypted_sha1_2des_wrong_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_2des.key", "PolarSLTest" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_122_pkcs8_encrypted_sha1_2des_no_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_2des.key", "" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_REQUIRED );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_ARC4_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_13_pkcs8_encrypted_sha1_rc4_128)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_rc4_128.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ARC4_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_ARC4_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_131_pkcs8_encrypted_sha1_rc4_128_wrong_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_rc4_128.key", "PolarSSLTe" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ARC4_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_ARC4_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS12_C

        FCT_TEST_BGN(x509_parse_key_132_pkcs8_encrypted_sha1_rc4_128_no_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbe_sha1_rc4_128.key", "" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_REQUIRED );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_ARC4_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS12_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_14_pkcs8_encrypted_v2_pbdfk2_3des)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_15_pkcs8_encrypted_v2_pbdfk2_3des_wrong_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.key", "PolarSSLTes" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_16_pkcs8_encrypted_v2_pbdfk2_3des_no_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.key", "" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_REQUIRED );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_17_pkcs8_encrypted_v2_pbdfk2_3des_der)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.der", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_18_pkcs8_encrypted_v2_pbdfk2_3des_der_wrong_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.der", "PolarSSLTes" );
        
            fct_chk( res == POLARSSL_ERR_X509_PASSWORD_MISMATCH );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_19_pkcs8_encrypted_v2_pbdfk2_3des_der_no_pw)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_3des.der", "" );
        
            fct_chk( res == POLARSSL_ERR_X509_KEY_INVALID_FORMAT );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_DES_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_PKCS5_C

        FCT_TEST_BGN(x509_parse_key_20_pkcs8_encrypted_v2_pbdfk2_des)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_keyfile( &rsa, "data_files/pkcs8_pbes2_pbkdf2_des.key", "PolarSSLTest" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_privkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_DES_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_PKCS5_C */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_parse_public_key_1_pkcs8_wrapped)
        {
            rsa_context rsa;
            int res;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
        
            res = x509parse_public_keyfile( &rsa, "data_files/format_gen.pub" );
        
            fct_chk( res == 0 );
        
            if( res == 0 )
            {
                fct_chk( rsa_check_pubkey( &rsa ) == 0 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_get_distinguished_name_1)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            res =  x509parse_dn_gets( buf, 2000, &crt.subject );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "C=NL, O=PolarSSL, CN=PolarSSL Server 1" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_get_distinguished_name_2)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            res =  x509parse_dn_gets( buf, 2000, &crt.issuer );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "C=NL, O=PolarSSL, CN=PolarSSL Test CA" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_get_distinguished_name_3)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            res =  x509parse_dn_gets( buf, 2000, &crt.subject );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "C=NL, O=PolarSSL, CN=localhost" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_get_distinguished_name_4)
        {
            x509_cert   crt;
            char buf[2000];
            int res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            res =  x509parse_dn_gets( buf, 2000, &crt.issuer );
        
            x509_free( &crt );
        
            fct_chk( res != -1 );
            fct_chk( res != -2 );
        
            fct_chk( strcmp( buf, "C=NL, O=PolarSSL, CN=PolarSSL Test CA" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_1)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_from ) == 1 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_2)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_to ) == 0 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_3)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_from ) == 1 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_4)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_to ) == 0 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_5)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_from ) == 1 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_expired_6polarssl_fs_io)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_time_expired( &crt.valid_to ) == 0 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_future_1)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_time_future( &crt.valid_from ) == 0 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_time_future_2)
        {
            x509_cert   crt;
        
            memset( &crt, 0, sizeof( x509_cert ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_time_future( &crt.valid_to ) == 1 );
        
            x509_free( &crt );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_1_revoked_cert_expired_crl)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED | BADCRL_EXPIRED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_2_revoked_cert_expired_crl)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "PolarSSL Server 1", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED | BADCRL_EXPIRED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_3_revoked_cert_expired_crl_cn_mismatch)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "PolarSSL Wrong CN", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED | BADCRL_EXPIRED | BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_4_valid_cert_expired_crl)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCRL_EXPIRED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_5_revoked_cert)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_6_revoked_cert)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "PolarSSL Server 1", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_7_revoked_cert_cn_mismatch)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "PolarSSL Wrong CN", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_REVOKED | BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_8_valid_cert)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_9_not_trusted_cert)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_NOT_TRUSTED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_10_not_trusted_cert_expired_crl)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_NOT_TRUSTED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD4_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_12_valid_cert_md4_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_md4.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_13_valid_cert_md5_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_md5.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_14_valid_cert_sha1_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha1.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_15_valid_cert_sha224_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha224.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_16_valid_cert_sha256_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha256.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_17_valid_cert_sha384_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha384.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_18_valid_cert_sha512_digest)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha512.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_19_valid_cert_denying_callback)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_sha512.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, verify_none, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_OTHER ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_20_not_trusted_cert_allowing_callback)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/server2.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/server1.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl_expired.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, NULL, &flags, verify_all, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_21_domain_matching_wildcard_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_wildcard.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "mail.ExAmPlE.com", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_22_domain_not_matching_wildcard_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_wildcard.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "mail.example.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_23_domain_not_matching_wildcard_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_wildcard.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "example.com", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_24_domain_matching_cn_of_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "www.example.com", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_25_domain_matching_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "example.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_26_domain_not_matching_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "www.example.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_27_domain_not_matching_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "xample.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_27_domain_not_matching_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "bexample.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_28_domain_not_matching_wildcard_in_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "example.org", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_29_domain_matching_wildcard_in_multi_certificate)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "mail.example.org", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( 0 ) );
            fct_chk( flags == ( 0 ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_30_domain_matching_multi_certificate_without_cn)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi_nocn.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "www.shotokan-braunschweig.de", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_NOT_TRUSTED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(x509_certificate_verification_31_domain_not_matching_multi_certificate_without_cn)
        {
            x509_cert   crt;
            x509_cert   ca;
            x509_crl    crl;
            int         flags = 0;
            int         res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( &ca, 0, sizeof( x509_cert ) );
            memset( &crl, 0, sizeof( x509_crl ) );
        
            fct_chk( x509parse_crtfile( &crt, "data_files/cert_example_multi_nocn.crt" ) == 0 );
            fct_chk( x509parse_crtfile( &ca, "data_files/test-ca.crt" ) == 0 );
            fct_chk( x509parse_crlfile( &crl, "data_files/crl.pem" ) == 0 );
        
            res = x509parse_verify( &crt, &ca, &crl, "www.example.net", &flags, NULL, NULL );
        
            x509_free( &crt );
            x509_free( &ca );
            x509_crl_free( &crl );
        
            fct_chk( res == ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED ) );
            fct_chk( flags == ( BADCERT_CN_MISMATCH + BADCERT_NOT_TRUSTED ) );
        }
        FCT_TEST_END();
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_PEM_C
#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(x509_parse_selftest)
        {
            fct_chk( x509_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_PEM_C */
#endif /* POLARSSL_SELF_TEST */


        FCT_TEST_BGN(x509_certificate_asn1_incorrect_first_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_data_length_does_not_match)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_no_more_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_length_data_incorrect)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30023085" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_length_data_incomplete)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30023083" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_length_data_incomplete)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30023081" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_length_data_incomplete)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3003308200" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_first_tag_second_tag_no_tbscertificate)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_no_version_tag_serial_missing)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3003300100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_invalid_version_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30053003a00101" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_version_tag_no_length)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30053003a00102" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_version_tag_invalid_length)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30163014a012021000000000000000000000000000000000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_version_tag_no_serial)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30073005a003020104" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA  ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA  ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_invalid_length_version_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30083006a00402010400" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_incorrect_serial_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30083006a00302010400" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_incorrect_serial_length)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30083006a00302010482" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_serial_no_alg)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300d300ba0030201048204deadbeef" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_serial_no_alg_oid)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300e300ca0030201048204deadbeef00" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_alg_oid_no_data_in_sequence)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300f300da0030201048204deadbeef3000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_alg_with_params)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30163014a0030201048204deadbeef30070604cafed00d01" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_data_no_params_unknown_version)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30153013a0030201048204deadbeef30060604cafed00d" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_data_unknown_version)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30173015a0030201048204deadbeef30080604cafed00d0500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_data_length_mismatch)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30183016a0030201048204deadbeef30090604cafed00d050000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_unknown_alg_id)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30173015a0030201028204deadbeef30080604cafed00d0500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_specific_alg_id)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "301c301aa0030201028204deadbeef300d06092a864886f70d0101020500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_correct_alg_unknown_specific_alg_id)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "301c301aa0030201028204deadbeef300d06092a864886f70d0101010500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_set_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "301e301ca0030201028204deadbeef300d06092a864886f70d01010205003000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_inner_seq_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3020301ea0030201028204deadbeef300d06092a864886f70d010102050030023100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_inner_set_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30223020a0030201028204deadbeef300d06092a864886f70d0101020500300431023000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_two_inner_set_datas)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30243022a0030201028204deadbeef300d06092a864886f70d01010205003006310430003000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_oid_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30243022a0030201028204deadbeef300d06092a864886f70d01010205003006310430020600" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_invalid_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "302a3028a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600060454657374" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_string_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30253023a0030201028204deadbeef300d06092a864886f70d0101020500300731053003060013" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_issuer_no_full_following_string)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "302b3029a0030201028204deadbeef300d06092a864886f70d0101020500300d310b3009060013045465737400" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE ) );
            if( ( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_issuer_no_validity)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "302a3028a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_too_much_date_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30493047a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301d170c303930313031303030303030170c30393132333132333539353900" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_invalid_from_date)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30483046a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303000000000170c303931323331323300000000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_invalid_to_date)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30483046a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323300000000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_validity_no_subject)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30493047a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c30393132333132333539353930" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_subject_no_pubkeyinfo)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30563054a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_no_alg)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30583056a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a300806001304546573743000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_valid_subject_unknown_pk_alg)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30673065a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374300f300d06092A864886F70D0101000500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_UNKNOWN_PK_ALG ) );
            if( ( POLARSSL_ERR_X509_UNKNOWN_PK_ALG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_no_bitstring)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30673065a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374300f300d06092A864886F70D0101010500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_no_bitstring_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30693067a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a300806001304546573743011300d06092A864886F70D01010105000300" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_invalid_bitstring_start)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "306a3068a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a300806001304546573743012300d06092A864886F70D0101010500030101" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_invalid_internal_bitstring_length)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "306d306ba0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a300806001304546573743015300d06092A864886F70D0101010500030400300000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_invalid_internal_bitstring_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "306d306ba0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a300806001304546573743015300d06092A864886F70D0101010500030400310000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_invalid_mpi)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30743072a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374301c300d06092A864886F70D0101010500030b0030080202ffff0302ffff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_total_length_mismatch)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30753073a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374301d300d06092A864886F70D0101010500030b0030080202ffff0202ffff00" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_check_failed)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30743072a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374301c300d06092A864886F70D0101010500030b0030080202ffff0202ffff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_RSA_KEY_CHECK_FAILED ) );
            if( ( POLARSSL_ERR_RSA_KEY_CHECK_FAILED ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_pubkey_check_failed_expanded_length_notation)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308183308180a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210fffffffffffffffffffffffffffffffe0202ffff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_RSA_KEY_CHECK_FAILED ) );
            if( ( POLARSSL_ERR_RSA_KEY_CHECK_FAILED ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_optional_uids_extensions_not_present)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308183308180a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_issuerid_wrong_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308184308181a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff00" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_uids_no_ext)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308189308186a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bb" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_uids_invalid_length)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308189308186a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa185aaa201bb" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_ASN1_INVALID_LENGTH ) );
            if( ( POLARSSL_ERR_ASN1_INVALID_LENGTH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_empty)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30818b308188a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba300" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_length_mismatch)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30818e30818ba0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba303300000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_first_ext_invalid)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30818f30818ca0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba30330023000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_first_ext_invalid_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30819030818da0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba3043002310000" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_bool_len_missing)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308198308195a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba30c300a30060603551d1301010100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_data_missing)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308198308195a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba30c300a30080603551d1301010100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_no_octet_present)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308198308195a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba30d300b30090603551d1301010100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_octet_data_missing)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30819c308199a0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba311300f300d0603551d130101010403300100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_no_pathlen)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30819f30819ca0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba314301230100603551d130101010406300402010102" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_tbscertificate_v3_ext_basiccontraint_tag_octet_len_mismatch)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3081a230819fa0030201028204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffffa101aaa201bba317301530130603551d130101010409300702010102010100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_extkeyusage_bad_second_tag)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308201ae308201aaa003020102020900a287596575d722e1300d06092a864886f70d0101050500300f310d300b0603550403130454657374301e170d3134313131373039323530345a170d3234313131343039323530345a300f310d300b060355040313045465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100c14da3dde7cd1dd104d74972b899ac0e78e43a3c4acf3a1316d05ae4cda30088a7ee1e6b96a752b490ef2d727a3e249afcb634ac24f577e026648c9cb0287da1daea8ce6c91c96bcfec10452b336d4a3fae1b176d890c161b4665236a22653aaab745e077d1982db2ad81fa0d90d1c2d4966f75b257346e80b8a4f690cb50090e1da8210667dae542b8b657991a1e261c3cd404908ee680cf18b86d246bfd0b8aa11031e7f56a81a1e44180f0f858bda8b445ee218c6622fc7668dfa5dd87df327892901c5900e3f27f130c84a0eefd6dec7c7276bc7053d7ac4023c9a1d3e0fe834985bcb734b5296d811a22c808869395ad30fb0de592f11c7f7ea120130970203010001a321301f301d0603551d250416301406082b0601050507030107082b06010505070302" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_subjectaltname_repeated)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308201cd308201c9a003020102020900a287596575d722e1300d06092a864886f70d0101050500300f310d300b0603550403130454657374301e170d3134313131373039323530345a170d3234313131343039323530345a300f310d300b060355040313045465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100c14da3dde7cd1dd104d74972b899ac0e78e43a3c4acf3a1316d05ae4cda30088a7ee1e6b96a752b490ef2d727a3e249afcb634ac24f577e026648c9cb0287da1daea8ce6c91c96bcfec10452b336d4a3fae1b176d890c161b4665236a22653aaab745e077d1982db2ad81fa0d90d1c2d4966f75b257346e80b8a4f690cb50090e1da8210667dae542b8b657991a1e261c3cd404908ee680cf18b86d246bfd0b8aa11031e7f56a81a1e44180f0f858bda8b445ee218c6622fc7668dfa5dd87df327892901c5900e3f27f130c84a0eefd6dec7c7276bc7053d7ac4023c9a1d3e0fe834985bcb734b5296d811a22c808869395ad30fb0de592f11c7f7ea120130970203010001a321301f301d0603551d11041630148208666f6f2e7465737482086261722e74657374301d0603551d11041630148208666f6f2e7465737482086261722e74657374" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_extkeyusage_repeated)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308201cd308201c9a003020102020900a287596575d722e1300d06092a864886f70d0101050500300f310d300b0603550403130454657374301e170d3134313131373039323530345a170d3234313131343039323530345a300f310d300b060355040313045465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100c14da3dde7cd1dd104d74972b899ac0e78e43a3c4acf3a1316d05ae4cda30088a7ee1e6b96a752b490ef2d727a3e249afcb634ac24f577e026648c9cb0287da1daea8ce6c91c96bcfec10452b336d4a3fae1b176d890c161b4665236a22653aaab745e077d1982db2ad81fa0d90d1c2d4966f75b257346e80b8a4f690cb50090e1da8210667dae542b8b657991a1e261c3cd404908ee680cf18b86d246bfd0b8aa11031e7f56a81a1e44180f0f858bda8b445ee218c6622fc7668dfa5dd87df327892901c5900e3f27f130c84a0eefd6dec7c7276bc7053d7ac4023c9a1d3e0fe834985bcb734b5296d811a22c808869395ad30fb0de592f11c7f7ea120130970203010001a340303e301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d250416301406082b0601050507030106082b06010505070302" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct_pubkey_no_sig_alg)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308183308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_sig_alg_mismatch)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308192308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0102020500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_SIG_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_SIG_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_sig_alg_no_sig)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308192308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_signature_invalid_sig_data)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308195308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030100" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_signature_data_left)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308197308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff00" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_correct)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308196308180a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : ?\?=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_generalizedtime_instead_of_utctime)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308198308182a0030201008204deadbeef300d06092a864886f70d0101020500300c310a30080600130454657374301e180e3230313030313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : ?\?=Test\nsubject name  : ?\?=Test\nissued  on    : 2010-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_cn)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b0603550403130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : CN=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_c)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b0603550406130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : C=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_l)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b0603550407130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : L=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_st)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b0603550408130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : ST=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_o)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b060355040a130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : O=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_x520_ou)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b060355040b130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : OU=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_unknown_x520_part)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "308199308183a0030201008204deadbeef300d06092a864886f70d0101020500300f310d300b06035504de130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : 0xDE=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_pkcs9_email)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30819f308189a0030201008204deadbeef300d06092a864886f70d010102050030153113301106092a864886f70d010901130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : emailAddress=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_certificate_asn1_name_with_unknown_pkcs9_part)
        {
            x509_cert   crt;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crt, 0, sizeof( x509_cert ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30819f308189a0030201008204deadbeef300d06092a864886f70d010102050030153113301106092a864886f70d0109ab130454657374301c170c303930313031303030303030170c303931323331323335393539300c310a30080600130454657374302a300d06092A864886F70D010101050003190030160210ffffffffffffffffffffffffffffffff0202ffff300d06092a864886f70d0101020500030200ff" );
        
            fct_chk( x509parse_crt( &crt, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_cert_info( (char *) output, 2000, "", &crt );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "cert. version : 1\nserial number : DE:AD:BE:EF\nissuer name   : 0xAB=Test\nsubject name  : ?\?=Test\nissued  on    : 2009-01-01 00:00:00\nexpires on    : 2009-12-31 23:59:59\nsigned using  : RSA+MD2\nRSA key size  : 128 bits\n" ) == 0 );
            }
        
            x509_free( &crt );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_incorrect_first_tag)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_correct_first_tag_data_length_does_not_match)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300000" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_tag_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3000" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_version_tag_len_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3003300102" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_version_correct_alg_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30053003020100" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_alg_correct_incorrect_version)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300b3009020102300406000500" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_correct_version_sig_oid1_unknown)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300b3009020100300406000500" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_sig_oid1_id_unknown)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30143012020100300d06092a864886f70d01010f0500" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) );
            if( ( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_sig_oid1_correct_issuer_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30143012020100300d06092a864886f70d01010e0500" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_issuer_set_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30163014020100300d06092a864886f70d01010e05003000" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_correct_issuer_thisupdate_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30253023020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_correct_thisupdate_nextupdate_missing_entries_length_missing)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30343032020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c30393031303130303030303030" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_ASN1_OUT_OF_DATA ) );
            if( ( POLARSSL_ERR_ASN1_OUT_OF_DATA ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_entries_present_invalid_sig_alg)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "304a3047020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030301430128202abcd170c30383132333132333539353900" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_entries_present_date_in_entry_invalid)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "304a3047020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030301430128202abcd190c30383132333132333539353900" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_sig_alg_present_sig_alg_does_not_match)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30583047020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030301430128202abcd170c303831323331323335393539300d06092a864886f70d01010d0500" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_SIG_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_SIG_MISMATCH ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_sig_present_len_mismatch)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "305d3047020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030301430128202abcd170c303831323331323335393539300d06092a864886f70d01010e05000302000100" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) );
            if( ( POLARSSL_ERR_X509_CERT_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_sig_present)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "305c3047020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030301430128202abcd170c303831323331323335393539300d06092a864886f70d01010e050003020001" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "CRL version   : 1\nissuer name   : CN=ABCD\nthis update   : 2009-01-01 00:00:00\nnext update   : 0000-00-00 00:00:00\nRevoked certificates:\nserial number: AB:CD revocation date: 2008-12-31 23:59:59\nsigned using  : RSA+SHA224\n" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_crl_asn1_tbscertlist_no_entries)
        {
            x509_crl   crl;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len, res;
        
            memset( &crl, 0, sizeof( x509_crl ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "30463031020100300d06092a864886f70d01010e0500300f310d300b0603550403130441424344170c303930313031303030303030300d06092a864886f70d01010e050003020001" );
        
            fct_chk( x509parse_crl( &crl, buf, data_len ) == ( 0 ) );
            if( ( 0 ) == 0 )
            {
                res = x509parse_crl_info( (char *) output, 2000, "", &crl );
                
                fct_chk( res != -1 );
                fct_chk( res != -2 );
        
                fct_chk( strcmp( (char *) output, "CRL version   : 1\nissuer name   : CN=ABCD\nthis update   : 2009-01-01 00:00:00\nnext update   : 0000-00-00 00:00:00\nRevoked certificates:\nsigned using  : RSA+SHA224\n" ) == 0 );
            }
        
            x509_crl_free( &crl );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_incorrect_first_tag)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_incorrect_version_tag)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300100" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_version_tag_missing)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3000" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_invalid_version)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "3003020101" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_correct_version_incorrect_tag)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "300402010000" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_values_present_length_mismatch)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "301c02010002010102010102010102010102010102010102010102010100" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(x509_key_asn1_rsaprivatekey_values_present_check_privkey_fails)
        {
            rsa_context   rsa;
            unsigned char buf[2000];
            unsigned char output[2000];
            int data_len;
        
            memset( &rsa, 0, sizeof( rsa_context ) );
            memset( buf, 0, 2000 );
            memset( output, 0, 2000 );
        
            data_len = unhexify( buf, "301b020100020101020101020101020101020101020101020101020101" );
        
            fct_chk( x509parse_key( &rsa, buf, data_len, NULL, 0 ) == ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) );
            if( ( POLARSSL_ERR_X509_KEY_INVALID_FORMAT ) == 0 )
            {
                fct_chk( 1 );
            }
        
            rsa_free( &rsa );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_X509_PARSE_C */
#endif /* POLARSSL_BIGNUM_C */

}
FCT_END();

