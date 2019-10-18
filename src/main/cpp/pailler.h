#ifndef __HEADER_PAILLER_H__
#define __HEADER_PAILLER_H__

#include "bn.h"
#include "common.h"
#include "macro.h"
//#include "windows.h"
#include <math.h>
#include "u8operation.h"

#ifdef  __cplusplus
extern "C" {
#endif
	void PAI_KeyGen(U8 *pbBN_n, U8 *pbBN_g, U8 *pbBN_lambda, U8 *pbBN_mu, S32 iBNWordLen);
	void PAI_Encryption(U8 *pbBN_c, U8 *pbBN_m, S32 nMessage_Len, U8 *pbBN_n, U8 *pbBN_g, U8 *pbRandom, S32 nRandom_Len, S32 iBNWordLen);
	void PAI_Decryption(U8 *pbBN_m, U8 *pbBN_c, U8 *pbBN_n, U8 *pbBN_lambda, U8 *pbBN_mu, S32 iBNWordLen);

	//Homomorphic addition of plaintexts
	void PAI_HomAdd(U8 *pbBN_Result, U8 *pbBN_c1, U8 *pbBN_c2, U8 *pbBN_n, S32 iBNWordLen);

	//Homomorphic multiplication of plaintexts
	void PAI_HomMul(U8 *pbBN_Result, U8 *pbBN_c1, U8 *pbBN_m2, S32 iM2WordLen, U8 *pbBN_n, S32 iBNWordLen);

#ifdef  __cplusplus
}
#endif


#endif

