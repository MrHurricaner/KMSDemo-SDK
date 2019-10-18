#include "common.h"


void SECP256K1_Init_Sys_Para(SECP256K1_Sys_Para *pSys_Para, U8 *pSysParaByte, S32  iBNWordLen)
{
	S32 bytelen = 0;
	U8 *pByteBuf = pSysParaByte;
	U32 nTemp = 0;

	//得到iBNWordLen
	pSys_Para->iBNWordLen = iBNWordLen;

	//得到q
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_Q, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到nConst_Q
	bytelen = 4;
	ByteToBN(pByteBuf, bytelen, &nTemp, iBNWordLen);
	pSys_Para->EC_nConst_Q = nTemp;
	pByteBuf = pByteBuf + bytelen;

	//得到R mod q
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_R_Q, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到RR mod q
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_RR_Q, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到n
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_N, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到nConst_N
	bytelen = 4;
	ByteToBN(pByteBuf, bytelen, &nTemp, iBNWordLen);
	pSys_Para->EC_nConst_N = nTemp;
	pByteBuf = pByteBuf + bytelen;

	//得到R mod n
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_R_N, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到RR mod n
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_RR_N, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到EC_Fp_A_Mont
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_Fp_A_Mont, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到EC_Fp_B_Mont
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_Fp_B_Mont, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到EC_Fp_G_Mont
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_Fp_G_Mont.X, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_Fp_G_Mont.Y, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

	//得到EC_One
	bytelen = 32;
	ByteToBN(pByteBuf, bytelen, pSys_Para->EC_One, iBNWordLen);
	pByteBuf = pByteBuf + bytelen;

}