#ifndef __HEADER_COMMON_H__
#define __HEADER_COMMON_H__

#include "bn.h"
/*
*��������U8����ת��ΪU32 ��
*/
#define GET_U32(n,b,i)                       \
{                                               \
	(n) = ( (U32) (b)[(i)    ] << 24 )       \
	| ( (U32) (b)[(i) + 1] << 16 )       \
	| ( (U32) (b)[(i) + 2] <<  8 )       \
	| ( (U32) (b)[(i) + 3]       );      \
}
/*
*��������32��ת��ΪU8����
*���룺U32��=��87654321 17654321 27654321 37654321��
*�����U8����= [0]="87654321"
*               [1]="17654321"
*               [2]="2......."
*               [3]="3......."
*/

#define PUT_U32(n,b,i)                       \
{                                               \
	(b)[(i)    ] = (U8) ( (n) >> 24 );       \
	(b)[(i) + 1] = (U8) ( (n) >> 16 );       \
	(b)[(i) + 2] = (U8) ( (n) >>  8 );       \
	(b)[(i) + 3] = (U8) ( (n)       );       \
}

#ifdef  __cplusplus
extern "C" {
#endif

	S32 ConvertHexChar(S8 ch, U8 *ch_byte);
	S32 CharToByte(S8 *pCharBuf, S32 charlen, S8 *pByteBuf, S32 *bytelen);
	S32 ByteToBN(U8 *pByteBuf, S32 bytelen, U32 *pwBN, S32 iBNWordLen);
	S32 BNToByte(U32 *pwBN,S32 iBNWordLen,U8 *pByteBuf,S32 *bytelen);

#ifdef  __cplusplus
}
#endif

#endif
