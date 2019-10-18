#ifndef _SHA256_H
#define _SHA256_H

#ifndef Byte
#define Byte  unsigned char
#endif

#ifndef Word32
#define Word32 unsigned long int
#endif

typedef struct
{
    Word32 total[2];
    Word32 state[8];
    Byte buffer[64];
}sha256_context;

#ifdef __cplusplus
extern "C" 
{
#endif

void sha256_starts( sha256_context *ctx );
void sha256_update( sha256_context *ctx, Byte *input, Word32 length );
void sha256_finish( sha256_context *ctx, Byte digest[32] );

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif /* sha2.h */

