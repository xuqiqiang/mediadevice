#include "fct.h"
#include <polarssl/config.h>

#include <polarssl/bignum.h>

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
#ifdef POLARSSL_BIGNUM_C


    FCT_SUITE_BGN(test_suite_mpi)
    {

        FCT_TEST_BGN(base_test_mpi_read_write_string_1)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "128" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 10, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "128" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_write_string_2)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "128" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 16, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "80" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_write_string_3_read_zero)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 10, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "0" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_write_string_3_negative_decimal)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "-23" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 10, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "-23" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_write_string_3_negative_hex)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "-20" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 10, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "-32" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_write_string_3_negative_decimal)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "-23" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 16, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "-23" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_1_invalid_character)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "a28" ) == POLARSSL_ERR_MPI_INVALID_CHARACTER );
            if( POLARSSL_ERR_MPI_INVALID_CHARACTER == 0 )
            {
                fct_chk( mpi_write_string( &X, 0, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_2_illegal_input_radix)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 19, "a28" ) == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( POLARSSL_ERR_MPI_BAD_INPUT_DATA == 0 )
            {
                fct_chk( mpi_write_string( &X, 0, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_3_buffer_just_fits)
        {
            mpi X;
            char str[1000];
            size_t len = 4;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "-23" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 16, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "-23" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_4_buffer_too_small)
        {
            mpi X;
            char str[1000];
            size_t len = 3;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "-23" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 16, str, &len ) == POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
                if( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL == 0 )
                {
                    fct_chk( strcasecmp( str, "-23" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_5_illegal_output_radix)
        {
            mpi X;
            char str[1000];
            size_t len = 4;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "-23" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 17, str, &len ) == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
                if( POLARSSL_ERR_MPI_BAD_INPUT_DATA == 0 )
                {
                    fct_chk( strcasecmp( str, "-23" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_6_output_radix_of_15)
        {
            mpi X;
            char str[1000];
            size_t len = 100;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "29" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 15, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "1e" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_read_write_string_7)
        {
            mpi X;
            char str[1000];
            size_t len = 200;
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( mpi_write_string( &X, 16, str, &len ) == 0 );
                if( 0 == 0 )
                {
                    fct_chk( strcasecmp( str, "0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" ) == 0 );
                }
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_read_binary_1)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t len = 1000;
            size_t input_len;
        
            mpi_init( &X );
        
            input_len = unhexify( buf, "0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" );
        
            fct_chk( mpi_read_binary( &X, buf, input_len ) == 0 );
            fct_chk( mpi_write_string( &X, 10, (char *) str, &len ) == 0 );
            fct_chk( strcmp( (char *) str, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_write_binary_1)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            
            buflen = mpi_size( &X );
            if( buflen > 200 )
                buflen = 200;
        
            fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
            if( 0 == 0)
            {
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_write_binary_1_buffer_just_fits)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "123123123123123123123123123" ) == 0 );
            
            buflen = mpi_size( &X );
            if( buflen > 14 )
                buflen = 14;
        
            fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
            if( 0 == 0)
            {
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "0123123123123123123123123123" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_write_binary_2_buffer_too_small)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "123123123123123123123123123" ) == 0 );
            
            buflen = mpi_size( &X );
            if( buflen > 13 )
                buflen = 13;
        
            fct_chk( mpi_write_binary( &X, buf, buflen ) == POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
            if( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL == 0)
            {
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "123123123123123123123123123" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(base_test_mpi_read_file_1)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
            FILE *file;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            file = fopen( "data_files/mpi_10", "r" );
            fct_chk( mpi_read_file( &X, 10, file ) == 0 );
            fclose(file);
        
            if( 0 == 0 )
            {
                buflen = mpi_size( &X );
                fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
        
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(test_mpi_read_file_1_empty_file)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
            FILE *file;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            file = fopen( "data_files/hash_file_4", "r" );
            fct_chk( mpi_read_file( &X, 10, file ) == POLARSSL_ERR_MPI_FILE_IO_ERROR );
            fclose(file);
        
            if( POLARSSL_ERR_MPI_FILE_IO_ERROR == 0 )
            {
                buflen = mpi_size( &X );
                fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
        
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(test_mpi_read_file_2_illegal_input)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
            FILE *file;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            file = fopen( "data_files/hash_file_3", "r" );
            fct_chk( mpi_read_file( &X, 10, file ) == 0 );
            fclose(file);
        
            if( 0 == 0 )
            {
                buflen = mpi_size( &X );
                fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
        
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(test_mpi_read_file_3_input_too_big)
        {
            mpi X;
            unsigned char str[1000];
            unsigned char buf[1000];
            size_t buflen;
            FILE *file;
        
            memset( buf, 0x00, 1000 );
            memset( str, 0x00, 1000 );
        
            mpi_init( &X );
        
            file = fopen( "data_files/mpi_too_big", "r" );
            fct_chk( mpi_read_file( &X, 10, file ) == POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
            fclose(file);
        
            if( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL == 0 )
            {
                buflen = mpi_size( &X );
                fct_chk( mpi_write_binary( &X, buf, buflen ) == 0 );
        
                hexify( str, buf, buflen );
        
                fct_chk( strcasecmp( (char *) str, "" ) == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(base_test_mpi_write_file_1)
        {
            mpi X, Y;
            FILE *file_out, *file_in;
        
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
        
            file_out = fopen( "data_files/mpi_write", "w" );
            fct_chk( file_out != NULL );
            fct_chk( mpi_write_file( NULL, &X, 16, file_out ) == 0 );
            fclose(file_out);
        
            file_in = fopen( "data_files/mpi_write", "r" );
            fct_chk( file_in != NULL );
            fct_chk( mpi_read_file( &Y, 16, file_in ) == 0 );
            fclose(file_in);
        
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();
#endif /* POLARSSL_FS_IO */


        FCT_TEST_BGN(base_test_mpi_lsb_1)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            fct_chk( mpi_lsb( &X ) == 2 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_lsb_2)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "24" ) == 0 );
            fct_chk( mpi_lsb( &X ) == 3 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_lsb_3)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "24" ) == 0 );
            fct_chk( mpi_lsb( &X ) == 2 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_lsb_4)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 16, "2000" ) == 0 );
            fct_chk( mpi_lsb( &X ) == 13 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_1)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            fct_chk( mpi_msb( &X ) == 764 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_2)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "24" ) == 0 );
            fct_chk( mpi_msb( &X ) == 5 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_3)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1" ) == 0 );
            fct_chk( mpi_msb( &X ) == 1 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_4)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "15" ) == 0 );
            fct_chk( mpi_msb( &X ) == 4 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_5)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "16" ) == 0 );
            fct_chk( mpi_msb( &X ) == 5 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_6)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "10" ) == 0 );
            fct_chk( mpi_msb( &X ) == 4 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_msb_7)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
            fct_chk( mpi_msb( &X ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_1)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, 693 ) == 0);
            fct_chk( mpi_cmp_int( &X, 693 ) == 0);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_2)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, 693 ) == 0);
            fct_chk( mpi_cmp_int( &X, 692 ) == 1);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_3)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, 693 ) == 0);
            fct_chk( mpi_cmp_int( &X, 694 ) == -1);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_negative_values_1)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, -2 ) == 0);
            fct_chk( mpi_cmp_int( &X, -2 ) == 0);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_negative_values_2)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, -2 ) == 0);
            fct_chk( mpi_cmp_int( &X, -3 ) == 1);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_int_negative_values_3)
        {
            mpi X;
            mpi_init( &X  );
        
            fct_chk( mpi_lset( &X, -2 ) == 0);
            fct_chk( mpi_cmp_int( &X, -1 ) == -1);
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "693" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_2)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "692" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_3)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "694" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_negative_values_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-2" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_negative_values_2)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-3" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_negative_values_3)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-1" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_mixed_values_4)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-3" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "2" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_mixed_values_5)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-3" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_mpi_mixed_values_6)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "31231231289798" ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "693" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_2)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "692" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_3)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "694" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_negative_values_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-2" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_negative_values_2)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-3" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_negative_values_3)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-1" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_zero_and_zero_4)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "0" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_mix_values_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "2" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_mix_values_2)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-3" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == -1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_cmp_abs_mix_values_3)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "-2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "1" ) == 0 );
            fct_chk( mpi_cmp_abs( &X, &Y ) == 1 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_copy_1)
        {
            mpi X, Y, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_lset( &X, 0 ) == 0 );
            fct_chk( mpi_lset( &Y, 1500 ) == 0 );
            fct_chk( mpi_lset( &A, 1500 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) != 0 );
            fct_chk( mpi_cmp_mpi( &Y, &A ) == 0 );
            fct_chk( mpi_copy( &Y, &X ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Y, &A ) != 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_copy_self_1)
        {
            mpi X;
            mpi_init( &X );
        
            fct_chk( mpi_lset( &X, 14 ) == 0 );
            fct_chk( mpi_copy( &X, &X ) == 0 );
            fct_chk( mpi_cmp_int( &X, 14 ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_swap_1)
        {
            mpi X, Y, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_lset( &X, 0 ) == 0 );
            fct_chk( mpi_lset( &Y, 1500 ) == 0 );
            fct_chk( mpi_lset( &A, 0 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) != 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            mpi_swap( &X, &Y );
            fct_chk( mpi_cmp_mpi( &X, &Y ) != 0 );
            fct_chk( mpi_cmp_mpi( &Y, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_abs_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12988209" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_abs_2)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12988209" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_abs_3)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12988209" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_abs_4)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12988209" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_abs_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-643808006803554439230129854961492699151386107534013432918073439524138264842370630061369715394739134090922937332590384720397133335969549256322620979036686633213903952966175107096769180017646161851573147596390153" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "56125680981752282333498088313568935051383833838594899821664631784577337171193624243181360054669678410455329112434552942717084003541384594864129940145043086760031292483340068923506115878221189886491132772739661669044958531131327771" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_abs_2_add_to_first_value)
        {
            mpi X, Y, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "123123" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "123123" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "246246" ) == 0 );
            fct_chk( mpi_add_abs( &X, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_abs_3_add_to_second_value)
        {
            mpi X, Y, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "123123" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "123123" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "246246" ) == 0 );
            fct_chk( mpi_add_abs( &Y, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Y, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(regression_mpi_add_abs_add_small_to_very_large_mpi_with_carry_rollover)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF8" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "08" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "1000000000000000000000000000000" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(regression_mpi_add_abs_add_small_to_very_large_mpi_with_carry_rollover)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "08" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF8" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "1000000000000000000000000000000" ) == 0 );
            fct_chk( mpi_add_abs( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_mpi_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12988209" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_mpi_2)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-11703147" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_mpi_3)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "11703147" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_add_mpi_4)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-12345678" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-642531" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-12988209" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_mpi_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "531872289054204184185084734375133399408303613982130856645299464930952178606045848877129147820387996428175564228204785846141207532462936339834139412401975338705794646595487324365194792822189473092273993580587964571659678084484152603881094176995594813302284232006001752128168901293560051833646881436219" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "735829167410606161590850601304167976688497607296479119740072111384235241328747126510065763883532084601487937110881909725679916932621242907172467691556475037071866553361927361439411910627880345885122142692610250903804554267860479115964668998643528806263534149325837971432443181537363155848647445226342" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_mpi_2)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "643808006803554439230129854961492699151386107534013432918073439524138264842370630061369715394739134090922937332590384720397133335969549256322620979036686633213903952966175107096769180017646161851573147596390153" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "56125680981752282333498088313568935051383833838594899821664631784577337171193624243181360054669678410455329112434552942717084003541384594864129940145043086760031292483340068923506115878221189886491132772739661669044958531131327771" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924" ) == 0 );
            fct_chk( mpi_add_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_int_1)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227022647561" ) == 0 );
            fct_chk( mpi_add_int( &Z, &X, 9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_add_int_2)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227002905097" ) == 0 );
            fct_chk( mpi_add_int( &Z, &X, -9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_1_test_with_larger_second_input)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_2_test_with_larger_second_input)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_3_test_with_larger_second_input)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_4_test_with_larger_second_input)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_1)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_2)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_3)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_abs_4)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_abs_1)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFF" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "01" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "FFFFFFFFFE" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_abs_2)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFF0" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "01" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "FFFFFFFFEF" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_abs_3)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FF00000000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "0F00000000" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "F000000000" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_abs_4)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FF00000000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "0F00000001" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "EFFFFFFFFF" ) == 0 );
            
            res = mpi_sub_abs( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_mpi_1_test_with_negative_result)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-2" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_mpi_2_test_with_negative_inputs)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_mpi_3_test_with_negative_base)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-12" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_sub_mpi_4_test_with_negative_substraction)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_mpi_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "531872289054204184185084734375133399408303613982130856645299464930952178606045848877129147820387996428175564228204785846141207532462936339834139412401975338705794646595487324365194792822189473092273993580587964571659678084484152603881094176995594813302284232006001752128168901293560051833646881436219" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "327915410697802206779318867446098822128109620667782593550526818477669115883344571244192531757243908254863191345527661966602498132304629772495811133247475640339722739829047287290977675016498600299425844468565678239514801901107826091797519355347660820341034314686165532823894621049756947818646317646096" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_mpi_2_test_for_negative_result)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "643808006803554439230129854961492699151386107534013432918073439524138264842370630061369715394739134090922937332590384720397133335969549256322620979036686633213903952966175107096769180017646161851573147596390153" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "56125680981752282333498088313568935051383833838594899821664631784577337171193624243181360054669678410455329112434552942717084003541384594864129940145043086760031292483340068923506115878221189886491132772739661669044958531131327771" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-56125680981752282332854280306765380612153703983633407122513245677043323738275550803657221789827307780393959397039813808626161066208794210143732806809073537503708671504303382290292211925255014779394363592722015507193385383534937618" ) == 0 );
            fct_chk( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_int_1)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227022647561" ) == 0 );
            fct_chk( mpi_sub_int( &Z, &X, -9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_sub_int_2)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227002905097" ) == 0 );
            fct_chk( mpi_sub_int( &Z, &X, 9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_l_1)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "64" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "128" ) == 0 );
            fct_chk( mpi_shift_l( &X, 1 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_l_2)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "658385546911733550164516088405238961461880256029834598831972039469421755117818013653494814438931957316403111689187691446941406788869098983929874080332195117465344344350008880118042764943201875870917468833709791733282363323948005998269792207" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "90487820548639020691922304619723076305400961610119884872723190678642804168382367856686134531865643066983017249846286450251272364365605022750900439437595355052945035915579216557330505438734955340526145476988250171181404966718289259743378883640981192704" ) == 0 );
            fct_chk( mpi_shift_l( &X, 37 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_1)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "128" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "64" ) == 0 );
            fct_chk( mpi_shift_r( &X, 1 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_2)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "120815570979701484704906977000760567182871429114712069861589084706550626575967516787438008593490722779337547394120718248995900363209947025063336882559539208430319216688889117222633155838468458047056355241515415159736436403445579777425189969" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "3433785053053426415343295076376096153094051405637175942660777670498379921354157795219578264137985649407981651226029903483433269093721578004287291678324982297860947730012217028349628999378309630601971640587504883789518896817457" ) == 0 );
            fct_chk( mpi_shift_r( &X, 45 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_4)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFFFFFFFF" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "01" ) == 0 );
            fct_chk( mpi_shift_r( &X, 63 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_4)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFFFFFFFF" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "00" ) == 0 );
            fct_chk( mpi_shift_r( &X, 64 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_6)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFFFFFFFF" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "00" ) == 0 );
            fct_chk( mpi_shift_r( &X, 65 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_shift_r_7)
        {
            mpi X, A;
            mpi_init( &X ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "FFFFFFFFFFFFFFFF" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "00" ) == 0 );
            fct_chk( mpi_shift_r( &X, 128 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mul_mpi_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "35" ) == 0 );
            fct_chk( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mul_mpi_2)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-35" ) == 0 );
            fct_chk( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mul_mpi_3)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-35" ) == 0 );
            fct_chk( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mul_mpi_4)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-5" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "35" ) == 0 );
            fct_chk( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_mul_mpi_1)
        {
            mpi X, Y, Z, A;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "28911710017320205966167820725313234361535259163045867986277478145081076845846493521348693253530011243988160148063424837895971948244167867236923919506962312185829914482993478947657472351461336729641485069323635424692930278888923450060546465883490944265147851036817433970984747733020522259537" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "16471581891701794764704009719057349996270239948993452268812975037240586099924712715366967486587417803753916334331355573776945238871512026832810626226164346328807407669366029926221415383560814338828449642265377822759768011406757061063524768140567867350208554439342320410551341675119078050953" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "476221599179424887669515829231223263939342135681791605842540429321038144633323941248706405375723482912535192363845116154236465184147599697841273424891410002781967962186252583311115708128167171262206919514587899883547279647025952837516324649656913580411611297312678955801899536937577476819667861053063432906071315727948826276092545739432005962781562403795455162483159362585281248265005441715080197800335757871588045959754547836825977169125866324128449699877076762316768127816074587766799018626179199776188490087103869164122906791440101822594139648973454716256383294690817576188761" ) == 0 );
            fct_chk( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_mul_int_1)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_mul_int( &Z, &X, 9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_mul_int_2_unsigned_thus_failure)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_mul_int( &Z, &X, -9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) != 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_mul_int_3)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_mul_int( &Z, &X, 9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_mul_int_4_unsigned_thus_failure)
        {
            mpi X, Z, A;
            mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-2039568783564019774057658669290345772801939933143482630947726464532830627227012776329" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_mul_int( &Z, &X, -9871232 ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) != 0 );
        
            mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_mpi_1)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "76" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "12" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_mpi_2_divide_by_zero)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "0" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "1" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "1" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_DIVISION_BY_ZERO );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_mpi_3)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-76" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "12" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_mpi_1)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "34" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "592148724779947824773845002981655249516095268533053127589864347174804198178334111238460803" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "26" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_mpi_2)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "476221599179424887669515829231223263939342135681791605842540429321038144633323941248706405375723482912535192363845116154236465184147599697841273424891410002781967962186252583311115708128167171262206919514587899883547279647025952837516324649656913580411611297312678955801899536937577476819667861053063432906071315727948826276092545739432005962781562403795455162483159362585281248265005441715080197800335757871588045959754547836825977169125866324128449699877076762316768127816074587766799018626179199776188490087103869164122906791440101822594139648973454716256383294690817576188762" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "28911710017320205966167820725313234361535259163045867986277478145081076845846493521348693253530011243988160148063424837895971948244167867236923919506962312185829914482993478947657472351461336729641485069323635424692930278888923450060546465883490944265147851036817433970984747733020522259537" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "16471581891701794764704009719057349996270239948993452268812975037240586099924712715366967486587417803753916334331355573776945238871512026832810626226164346328807407669366029926221415383560814338828449642265377822759768011406757061063524768140567867350208554439342320410551341675119078050953" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "1" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_mpi_3)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "142" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "6" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_mpi_4)
        {
            mpi X, Y, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
            mpi_init( &A ); mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "777" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "7" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "111" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "0" ) == 0 );
            res = mpi_div_mpi( &Q, &R, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
            mpi_free( &A ); mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_int_1)
        {
            mpi X, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
            mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "76" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "12" ) == 0 );
            res = mpi_div_int( &Q, &R, &X, 13 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
            mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_int_2_divide_by_zero)
        {
            mpi X, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
            mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "1" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "1" ) == 0 );
            res = mpi_div_int( &Q, &R, &X, 0 );
            fct_chk( res == POLARSSL_ERR_MPI_DIVISION_BY_ZERO );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
            mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_div_int_3)
        {
            mpi X, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
            mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-76" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "12" ) == 0 );
            res = mpi_div_int( &Q, &R, &X, -13 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
            mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_int_1)
        {
            mpi X, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
            mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "592148724779947824773845002981655249516095268533053127589864347174804198178334111238460803" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "26" ) == 0 );
            res = mpi_div_int( &Q, &R, &X, 34 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
            mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_div_int_2)
        {
            mpi X, Q, R, A, B;
            int res;
            mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
            mpi_init( &B );
        
            fct_chk( mpi_read_string( &X, 10, "20133056642518226042310730101376278483547239130123806338055387803943342738063359782107667328" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-592148724779947824773845002981655249516095268533053127589864347174804198178334111238460803" ) == 0 );
            fct_chk( mpi_read_string( &B, 10, "26" ) == 0 );
            res = mpi_div_int( &Q, &R, &X, -34 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Q, &A ) == 0 );
                fct_chk( mpi_cmp_mpi( &R, &B ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
            mpi_free( &B );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_mpi_1)
        {
            mpi X, Y, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "12" ) == 0 );
            res = mpi_mod_mpi( &X, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_mpi_2_divide_by_zero)
        {
            mpi X, Y, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "0" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            res = mpi_mod_mpi( &X, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_DIVISION_BY_ZERO );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_mpi_3)
        {
            mpi X, Y, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "1" ) == 0 );
            res = mpi_mod_mpi( &X, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_mpi_4_negative_modulo)
        {
            mpi X, Y, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-1" ) == 0 );
            res = mpi_mod_mpi( &X, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_mpi_5_negative_modulo)
        {
            mpi X, Y, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "-1000" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-13" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "-12" ) == 0 );
            res = mpi_mod_mpi( &X, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &X, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_1)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            res = mpi_mod_int( &r, &X, 13 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( r == 12 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_2_divide_by_zero)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            res = mpi_mod_int( &r, &X, 0 );
            fct_chk( res == POLARSSL_ERR_MPI_DIVISION_BY_ZERO );
            if( res == 0 )
            {
                fct_chk( r == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_3)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "-1000" ) == 0 );
            res = mpi_mod_int( &r, &X, 13 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( r == 1 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_4_negative_modulo)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            res = mpi_mod_int( &r, &X, -13 );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
            {
                fct_chk( r == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_5_negative_modulo)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "-1000" ) == 0 );
            res = mpi_mod_int( &r, &X, -13 );
            fct_chk( res == POLARSSL_ERR_MPI_NEGATIVE_VALUE );
            if( res == 0 )
            {
                fct_chk( r == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_6_by_1)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            res = mpi_mod_int( &r, &X, 1 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( r == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_7_by_2)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1001" ) == 0 );
            res = mpi_mod_int( &r, &X, 2 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( r == 1 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_mod_int_8_by_2)
        {
            mpi X;
            int res;
            t_uint r;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1000" ) == 0 );
            res = mpi_mod_int( &r, &X, 2 );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( r == 0 );
            }
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_1)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "29" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "24" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_2_even_n)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "30" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_3_negative_n)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "-29" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_4_negative_base)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "-23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "29" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_5_negative_exponent)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "-13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "29" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_mpi_exp_mod_7_negative_base__exponent)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "-23" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "-13" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "29" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_exp_mod_1)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "433019240910377478217373572959560109819648647016096560523769010881172869083338285573756574557395862965095016483867813043663981946477698466501451832407592327356331263124555137732393938242285782144928753919588632679050799198937132922145084847" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "5781538327977828897150909166778407659250458379645823062042492461576758526757490910073628008613977550546382774775570888130029763571528699574717583228939535960234464230882573615930384979100379102915657483866755371559811718767760594919456971354184113721" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "583137007797276923956891216216022144052044091311388601652961409557516421612874571554415606746479105795833145583959622117418531166391184939066520869800857530421873250114773204354963864729386957427276448683092491947566992077136553066273207777134303397724679138833126700957" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "114597449276684355144920670007147953232659436380163461553186940113929777196018164149703566472936578890991049344459204199888254907113495794730452699842273939581048142004834330369483813876618772578869083248061616444392091693787039636316845512292127097865026290173004860736" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_exp_mod_negative_base)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 10, "-10000000000" ) == 0 );
            fct_chk( mpi_read_string( &E, 10, "10000000000" ) == 0 );
            fct_chk( mpi_read_string( &N, 10, "99999" ) == 0 );
            fct_chk( mpi_read_string( &X, 10, "99998" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 10, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_mpi_exp_mod_negative_base)
        {
            mpi A, E, N, RR, Z, X;
            int res;
            mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
            mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );
        
            fct_chk( mpi_read_string( &A, 16, "-9f13012cd92aa72fb86ac8879d2fde4f7fd661aaae43a00971f081cc60ca277059d5c37e89652e2af2585d281d66ef6a9d38a117e9608e9e7574cd142dc55278838a2161dd56db9470d4c1da2d5df15a908ee2eb886aaa890f23be16de59386663a12f1afbb325431a3e835e3fd89b98b96a6f77382f458ef9a37e1f84a03045c8676ab55291a94c2228ea15448ee96b626b998" ) == 0 );
            fct_chk( mpi_read_string( &E, 16, "40a54d1b9e86789f06d9607fb158672d64867665c73ee9abb545fc7a785634b354c7bae5b962ce8040cf45f2c1f3d3659b2ee5ede17534c8fc2ec85c815e8df1fe7048d12c90ee31b88a68a081f17f0d8ce5f4030521e9400083bcea73a429031d4ca7949c2000d597088e0c39a6014d8bf962b73bb2e8083bd0390a4e00b9b3" ) == 0 );
            fct_chk( mpi_read_string( &N, 16, "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3" ) == 0 );
            fct_chk( mpi_read_string( &X, 16, "21acc7199e1b90f9b4844ffe12c19f00ec548c5d32b21c647d48b6015d8eb9ec9db05b4f3d44db4227a2b5659c1a7cceb9d5fa8fa60376047953ce7397d90aaeb7465e14e820734f84aa52ad0fc66701bcbb991d57715806a11531268e1e83dd48288c72b424a6287e9ce4e5cc4db0dd67614aecc23b0124a5776d36e5c89483" ) == 0 );
        
            if( strlen( "" ) )
                fct_chk( mpi_read_string( &RR, 16, "" ) == 0 );
        
            res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &X ) == 0 );
            }
        
            mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
            mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_gcd_1)
        {
            mpi A, X, Y, Z;
            mpi_init( &A ); mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
        
            fct_chk( mpi_read_string( &X, 10, "693" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "609" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "21" ) == 0 );
            fct_chk( mpi_gcd( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &A ); mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_gcd_2)
        {
            mpi A, X, Y, Z;
            mpi_init( &A ); mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
        
            fct_chk( mpi_read_string( &X, 10, "1764" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "868" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "28" ) == 0 );
            fct_chk( mpi_gcd( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &A ); mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base_test_gcd_3)
        {
            mpi A, X, Y, Z;
            mpi_init( &A ); mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
        
            fct_chk( mpi_read_string( &X, 10, "768454923" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "542167814" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "1" ) == 0 );
            fct_chk( mpi_gcd( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &A ); mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_gcd_1)
        {
            mpi A, X, Y, Z;
            mpi_init( &A ); mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
        
            fct_chk( mpi_read_string( &X, 10, "433019240910377478217373572959560109819648647016096560523769010881172869083338285573756574557395862965095016483867813043663981946477698466501451832407592327356331263124555137732393938242285782144928753919588632679050799198937132922145084847" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "5781538327977828897150909166778407659250458379645823062042492461576758526757490910073628008613977550546382774775570888130029763571528699574717583228939535960234464230882573615930384979100379102915657483866755371559811718767760594919456971354184113721" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "1" ) == 0 );
            fct_chk( mpi_gcd( &Z, &X, &Y ) == 0 );
            fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
        
            mpi_free( &A ); mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
        }
        FCT_TEST_END();

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_inv_mod_1)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "3" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "11" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "4" ) == 0 );
            res = mpi_inv_mod( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_inv_mod_2)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "3" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "0" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            res = mpi_inv_mod( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_inv_mod_3)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "3" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "-11" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "4" ) == 0 );
            res = mpi_inv_mod( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_BAD_INPUT_DATA );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_inv_mod_4)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 10, "2" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "4" ) == 0 );
            fct_chk( mpi_read_string( &A, 10, "0" ) == 0 );
            res = mpi_inv_mod( &Z, &X, &Y );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_inv_mod_1)
        {
            mpi X, Y, Z, A;
            int res;
            mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );
        
            fct_chk( mpi_read_string( &X, 16, "aa4df5cb14b4c31237f98bd1faf527c283c2d0f3eec89718664ba33f9762907c" ) == 0 );
            fct_chk( mpi_read_string( &Y, 16, "fffbbd660b94412ae61ead9c2906a344116e316a256fd387874c6c675b1d587d" ) == 0 );
            fct_chk( mpi_read_string( &A, 16, "8d6a5c1d7adeae3e94b9bcd2c47e0d46e778bc8804a2cc25c02d775dc3d05b0c" ) == 0 );
            res = mpi_inv_mod( &Z, &X, &Y );
            fct_chk( res == 0 );
            if( res == 0 )
            {
                fct_chk( mpi_cmp_mpi( &Z, &A ) == 0 );
            }
        
            mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_1)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "0" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_2)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "1" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_3)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "2" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_4)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "3" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_5)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "4" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_6)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "5" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_7)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "27" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(base_test_mpi_is_prime_8)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "47" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_1)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "827131507221654563937832686696200995595835694437983658840870036586124168186967796809117749047430768825822857042432722828096779098498192459819306321073968735177531164565305635281198148032612029767584644305912099" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_2)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "827131507221654563937832686696200995595835694437983658840870036586124168186967796809117749047430768825822857042432722828096779098498192459819306321073968735177531164565305635281198148032612029767584644305912001" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_3)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "2833419889721787128217599" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_4)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "195845982777569926302400511" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_5)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "4776913109852041418248056622882488319" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_5)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "768614336404564651" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_6)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "201487636602438195784363" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_7)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "845100400152152934331135470251" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_8)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "56713727820156410577229101238628035243" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_9)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_10)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "531872289054204184185084734375133399408303613982130856645299464930952178606045848877129147820387996428175564228204785846141207532462936339834139412401975338705794646595487324365194792822189473092273993580587964571659678084484152603881094176995594813302284232006001752128168901293560051833646881436219" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_11)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "319705304701141539155720137200974664666792526059405792539680974929469783512821793995613718943171723765238853752439032835985158829038528214925658918372196742089464683960239919950882355844766055365179937610326127675178857306260955550407044463370239890187189750909036833976197804646589380690779463976173" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_12)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "200603822195324642393516294012917598972967449320074999667103434371470616000652036570009912021332527788252300901905236578801044680456930305350440933538867383130165841118050781326291059830545891570648243241795871" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_13)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "827131507221654563937832686696200995595835694437983658840870036586124168186967796809117749047430768825822857042432722828096779098498192459819306321073968735177531164565305635281198148032612029767584644305912099" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_14)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "964274047248418797145090983157197980855078966882276492572788532954904112655338439361306213898569516593744267391754033306465125919199692703323878557833023573312685002670662846477592597659826113460619815244721311" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_15)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "170141183460469231731687303715884105727" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_16)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "2147483647" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_17)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "961748941" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_18)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "179424691" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_19)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "32452867" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */

#ifdef POLARSSL_GENPRIME

        FCT_TEST_BGN(test_mpi_is_prime_20)
        {
            mpi X;
            int res;
            mpi_init( &X );
        
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            res = mpi_is_prime( &X, rnd_std_rand, NULL );
            fct_chk( res == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();
#endif /* POLARSSL_GENPRIME */


        FCT_TEST_BGN(test_bit_getting_value_bit_25)
        {
            mpi X;
            mpi_init( &X );
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_get_bit( &X, 25 ) == 1 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_getting_larger_but_same_limb)
        {
            mpi X;
            mpi_init( &X );
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_get_bit( &X, 26 ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_getting_larger_and_non_existing_limb)
        {
            mpi X;
            mpi_init( &X );
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_get_bit( &X, 500 ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_getting_value_bit_24)
        {
            mpi X;
            mpi_init( &X );
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_get_bit( &X, 24 ) == 0 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_getting_value_bit_23)
        {
            mpi X;
            mpi_init( &X );
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_get_bit( &X, 23 ) == 1 );
        
            mpi_free( &X );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_set_change_existing_value_with_a_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "66756903" ) == 0 );
            fct_chk( mpi_set_bit( &X, 24, 1 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_set_change_existing_value_with_a_0)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "16425255" ) == 0 );
            fct_chk( mpi_set_bit( &X, 25, 0 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_set_add_above_existing_limbs_with_a_0)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "49979687" ) == 0 );
            fct_chk( mpi_set_bit( &X, 80, 0 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_bit_set_add_above_existing_limbs_with_a_1)
        {
            mpi X, Y;
            mpi_init( &X ); mpi_init( &Y );
        
            fct_chk( mpi_read_string( &X, 10, "49979687" ) == 0 );
            fct_chk( mpi_read_string( &Y, 10, "1208925819614629224685863" ) == 0 );
            fct_chk( mpi_set_bit( &X, 80, 1 ) == 0 );
            fct_chk( mpi_cmp_mpi( &X, &Y ) == 0 );
        
            mpi_free( &X ); mpi_free( &Y );
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(mpi_selftest)
        {
            fct_chk( mpi_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_BIGNUM_C */

}
FCT_END();

