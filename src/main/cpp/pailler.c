#include "pailler.h"

/*
功能：产生pailler系统公私钥
输入：素数p,q的长度
输出：系统参数n,g,lambda,mu
*/
void PAI_KeyGen(U8 *pbBN_n, U8 *pbBN_g, U8 *pbBN_lambda, U8 *pbBN_mu, S32 iBNWordLen)
{
	/****************************/
	U32 BN_N[BNMAXWordLen];
	U32 BN_G[BNMAXWordLen];
	U32 BN_Lambda[BNMAXWordLen];
	U32 BN_Mu[BNMAXWordLen];
	U32 BN_P[BNMAXWordLen];
	U32 BN_Q[BNMAXWordLen];
	U32 BN_T1[BNMAXWordLen];
	U32 BN_T2[BNMAXWordLen];
	U32 BN_One[BNMAXWordLen];
	S32 result = 0;
	S32 len = 0;
	/****************************/
	BN_Reset(BN_N, BNMAXWordLen);
	BN_Reset(BN_G, BNMAXWordLen);
	BN_Reset(BN_Lambda, BNMAXWordLen);
	BN_Reset(BN_Mu, BNMAXWordLen);
	BN_Reset(BN_P, BNMAXWordLen);
	BN_Reset(BN_Q, BNMAXWordLen);
	BN_Reset(BN_T1, BNMAXWordLen);
	BN_Reset(BN_T2, BNMAXWordLen);
	BN_Reset(BN_One, BNMAXWordLen);

	BN_One[0] = LSBOfWord;
	BN_GenPrime(BN_P, iBNWordLen);
	BN_GenPrime(BN_Q, iBNWordLen);
	//p-1
	BN_Sub(BN_T1, BN_P, BN_One, iBNWordLen);
	//q-1
	BN_Sub(BN_T2, BN_Q, BN_One, iBNWordLen);
	//n = pq
	BN_Mul(BN_N, BN_P, BN_Q, iBNWordLen);
	result = BNToByte(BN_N, 2*iBNWordLen, pbBN_n, &len);
	//g = n+1;
	BN_Add(BN_G, BN_N, BN_One, 2*iBNWordLen);
	result = BNToByte(BN_G, 2*iBNWordLen, pbBN_g, &len);
	//lambda=(p-1)(q-1)
	BN_Mul(BN_Lambda, BN_T1, BN_T2, iBNWordLen);
	result = BNToByte(BN_Lambda, 2*iBNWordLen, pbBN_lambda, &len);
	//mu = (lambda)^(-1) mod n
	BN_GetInv(BN_Mu, BN_Lambda, BN_N, 2*iBNWordLen);
	result = BNToByte(BN_Mu, 2*iBNWordLen, pbBN_mu, &len);
}


/*
功能：paillier加密，密文c = g^m * r^n mod n^2.
输入：待加密消息m，消息的长度，公钥（n,g）,随机数r，随机数长度，n的长度
输出：密文c
*/
void PAI_Encryption(U8 *pbBN_c, U8 *pbBN_m, S32 nMessage_Len, U8 *pbBN_n, U8 *pbBN_g, U8 *pbRandom, S32 nRandom_Len, S32 iBNWordLen)
{
	/******************/
	U32 BN_r[BNMAXWordLen];
	U32 BN_N[BNMAXWordLen];
	U32 BN_N2[BNMAXWordLen];
	U32 BN_C[BNMAXWordLen];
	U32 BN_R[BNMAXWordLen];
	U32 BN_R2[BNMAXWordLen];
	U32 BN_gm[BNMAXWordLen];
	U32 BN_rn[BNMAXWordLen];
	U32 BN_g[BNMAXWordLen];
	U32 BN_One[BNMAXWordLen];
	U32 BN_M[BNMAXWordLen];

	S32 loglen = 0;
	U32 wModuleConst = 0;
	S32 len = 0;
	S32 result = 0;
	/******************/
	BN_Reset(BN_r, BNMAXWordLen);
	BN_Reset(BN_N, BNMAXWordLen);
	BN_Reset(BN_N2, BNMAXWordLen);
	BN_Reset(BN_C, BNMAXWordLen);
	BN_Reset(BN_R, BNMAXWordLen);
	BN_Reset(BN_R2, BNMAXWordLen);
	BN_Reset(BN_gm, BNMAXWordLen);
	BN_Reset(BN_rn, BNMAXWordLen);
	BN_Reset(BN_g, BNMAXWordLen);
	BN_Reset(BN_One, BNMAXWordLen);
	BN_Reset(BN_M, BNMAXWordLen);

	BN_One[0] = LSBOfWord;
	//m
	result = ByteToBN(pbBN_m, nMessage_Len, BN_M, iBNWordLen);
	//n
	result = ByteToBN(pbBN_n, 4*iBNWordLen, BN_N, iBNWordLen);
	//g
	result = ByteToBN(pbBN_g, 4*iBNWordLen, BN_g, iBNWordLen);
	//r
	result = ByteToBN(pbRandom, nRandom_Len, BN_r, iBNWordLen);
	//r mod n
	BN_GetLastRes(BN_r, BN_N, iBNWordLen);

	//Prepare Montgomery Mul with n^2
	BN_Mul(BN_N2, BN_N, BN_N, iBNWordLen);//n^2
	wModuleConst = BN_GetMontConst(BN_N2[0], 32);
	BN_GetR(BN_R, BN_N2, 2*iBNWordLen);//R = 0-n^2
	loglen = PaiLogLen + 1;//RR,11 = log(bitlength)
	BN_GetR2(BN_R2, BN_R, BN_N2, wModuleConst, 2*iBNWordLen, loglen);//2^11
	BN_GetLastRes(BN_R2, BN_N2, 2*iBNWordLen);

	//g^m
	BN_ModMul_Mont(BN_g, BN_g, BN_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModExp(BN_gm, BN_g, BN_M, BN_N2, wModuleConst, 2*iBNWordLen);
	if(BN_IsZero(BN_M, 2*iBNWordLen) != 1)
	{	
		BN_ModMul_Mont(BN_gm, BN_gm, BN_One, BN_N2, wModuleConst, 2*iBNWordLen);
		BN_GetLastRes(BN_gm, BN_N2, 2*iBNWordLen);
	}
	//r^n
	BN_ModMul_Mont(BN_r, BN_r, BN_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModExp(BN_rn, BN_r, BN_N, BN_N2, wModuleConst, 2*iBNWordLen);
	//g^m*r^n mod n^2
	//BN_ModMul_Mont(BN_gm, BN_gm, BN_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModMul_Mont(BN_C, BN_gm, BN_rn, BN_N2, wModuleConst, 2*iBNWordLen);
	//BN_ModMul_Mont(BN_C, BN_C, BN_One, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_GetLastRes(BN_C, BN_N2, 2*iBNWordLen);

	result = BNToByte(BN_C, 2*iBNWordLen, pbBN_c, &len);
	
}
/*
功能：paillier解密，m = L(c^lambda mod n^2) * mu mod n, 其中mu = (L(g^lambda mod n^2))^(-1) mod n.
输入：加密密文c，消息的长度，私钥（lambda,mu）,公钥n
输出：明文m
*/
void PAI_Decryption(U8 *pbBN_m, U8 *pbBN_c, U8 *pbBN_n, U8 *pbBN_lambda, U8 *pbBN_mu, S32 iBNWordLen)
{
	/*****************************/
	U32 BN_N[BNMAXWordLen];
	U32 BN_Mu[BNMAXWordLen];
	U32 BN_Lambda[BNMAXWordLen];
	U32 BN_C[BNMAXWordLen];
	U32 BN_clambda[BNMAXWordLen];
	U32 BN_N2[BNMAXWordLen];
	U32 BN_rem[BNMAXWordLen];
	U32 BN_quo[BNMAXWordLen];
	U32 BN_One[BNMAXWordLen];
	U32 BN_T[BNMAXWordLen];

	U32 wModuleConst = 0;
	U32 BN_N2_R[BNMAXWordLen];
	U32 BN_N2_R2[BNMAXWordLen];
	U32 BN_N_R[BNMAXWordLen];
	U32 BN_N_R2[BNMAXWordLen];
	S32 len = 0;
	S32 loglen = 0;
	S32 result = 0;
	/**********************************/
	BN_Reset(BN_N, BNMAXWordLen);
	BN_Reset(BN_Mu, BNMAXWordLen);
	BN_Reset(BN_Lambda, BNMAXWordLen);
	BN_Reset(BN_C, BNMAXWordLen);
	BN_Reset(BN_clambda, BNMAXWordLen);
	BN_Reset(BN_N2, BNMAXWordLen);
	BN_Reset(BN_rem, BNMAXWordLen);
	BN_Reset(BN_quo, BNMAXWordLen);
	BN_Reset(BN_One, BNMAXWordLen);
	BN_Reset(BN_T, BNMAXWordLen);

	BN_Reset(BN_N2_R, BNMAXWordLen);
	BN_Reset(BN_N2_R2, BNMAXWordLen);
	BN_Reset(BN_N_R, BNMAXWordLen);
	BN_Reset(BN_N_R2, BNMAXWordLen);

	BN_One[0] = LSBOfWord;

	result = ByteToBN(pbBN_c, 8*iBNWordLen, BN_C, 2*iBNWordLen);
	result = ByteToBN(pbBN_n, 4*iBNWordLen, BN_N, iBNWordLen);
	result = ByteToBN(pbBN_lambda, 4*iBNWordLen, BN_Lambda, iBNWordLen);
	result = ByteToBN(pbBN_mu, 4*iBNWordLen, BN_Mu, iBNWordLen);

	//Prepare Montgomery Mul with n^2
	BN_Mul(BN_N2, BN_N, BN_N, iBNWordLen);//N2
	wModuleConst = BN_GetMontConst(BN_N2[0], 32);
	BN_GetR(BN_N2_R, BN_N2, 2*iBNWordLen);//N^2 R
	loglen = PaiLogLen + 1;
	BN_GetR2(BN_N2_R2, BN_N2_R, BN_N2, wModuleConst, 2*iBNWordLen, loglen);//N^2 RR
	BN_GetLastRes(BN_N2_R2, BN_N2, 2*iBNWordLen);

	//c^(lambda) mod n^2
	BN_ModMul_Mont(BN_C, BN_C, BN_N2_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModExp(BN_clambda, BN_C, BN_Lambda, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModMul_Mont(BN_clambda, BN_clambda, BN_One, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_GetLastRes(BN_clambda, BN_N2, 2*iBNWordLen);

	//L{c^(lambda)}函数, L{x} = (x - 1) / n
	BN_Sub(BN_T, BN_clambda, BN_One, 2*iBNWordLen);
	BN_Div(BN_rem, BN_quo, BN_T, 2*iBNWordLen, BN_N, iBNWordLen);
	BN_Assign(BN_T, BN_quo, iBNWordLen);
	wModuleConst = BN_GetMontConst(BN_N[0], 32);
	BN_GetR(BN_N_R, BN_N, iBNWordLen);
	loglen = PaiLogLen;
	BN_GetR2(BN_N_R2, BN_N_R, BN_N, wModuleConst, iBNWordLen, loglen);
	BN_ModMul_Mont(BN_T, BN_T, BN_N_R2, BN_N, wModuleConst, iBNWordLen);
	BN_ModMul_Mont(BN_Mu, BN_Mu, BN_N_R2, BN_N, wModuleConst, iBNWordLen);
	BN_ModMul_Mont(BN_T, BN_T, BN_Mu, BN_N, wModuleConst, iBNWordLen);
	BN_ModMul_Mont(BN_T, BN_T, BN_One, BN_N, wModuleConst, iBNWordLen);
	BN_GetLastRes(BN_T, BN_N, iBNWordLen);

	result = BNToByte(BN_T, iBNWordLen, pbBN_m, &len);
}
/*
功能：paillier加法同态, c^* = E(m1)*E(m2) mod n^2
输入：加密密文数组,密文个数, 公钥n
输出：新密文
*/
void PAI_HomAdd(U8 *pbBN_Result, U8 *pbBN_c1, U8 *pbBN_c2, U8 *pbBN_n, S32 iBNWordLen)
{
	/****************************/
	U32 BN_N2[BNMAXWordLen];
	U32 BN_N[BNMAXWordLen];
	U32 BN_R[BNMAXWordLen];
	U32 BN_R2[BNMAXWordLen];
	U32 BN_C1[BNMAXWordLen];
	U32 BN_C2[BNMAXWordLen];
	U32 BN_C3[BNMAXWordLen];
	U32 BN_One[BNMAXWordLen];
	U32 wModuleConst = 0;

	U8 bBN_T[8*BNMAXWordLen] = {0};
	S32 i = 0;
	S32 len = 0;
	S32 loglen = 0;
	S32 result = 0;
	/****************************/
	BN_Reset(BN_N2, BNMAXWordLen);
	BN_Reset(BN_N, BNMAXWordLen);
	BN_Reset(BN_R, BNMAXWordLen);
	BN_Reset(BN_R2, BNMAXWordLen);
	BN_Reset(BN_C1, BNMAXWordLen);
	BN_Reset(BN_C2, BNMAXWordLen);
	BN_Reset(BN_C3, BNMAXWordLen);
	BN_Reset(BN_One, BNMAXWordLen);
	BN_One[0] = LSBOfWord;

	result = ByteToBN(pbBN_n, 4*iBNWordLen, BN_N, iBNWordLen);
	result = ByteToBN(pbBN_c1, 8*iBNWordLen, BN_C1, 2*iBNWordLen);
	result = ByteToBN(pbBN_c2, 8*iBNWordLen, BN_C2, 2*iBNWordLen);

	//Prepare Montgomery Mul with n^2
	BN_Mul(BN_N2, BN_N, BN_N, iBNWordLen);
	wModuleConst = BN_GetMontConst(BN_N2[0], 32);
	BN_GetR(BN_R, BN_N2, 2*iBNWordLen);
	loglen = PaiLogLen + 1;
	BN_GetR2(BN_R2, BN_R, BN_N2, wModuleConst, 2*iBNWordLen, loglen);
	BN_GetLastRes(BN_R2, BN_N2, 2*iBNWordLen);

	BN_ModMul_Mont(BN_C1, BN_C1, BN_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModMul_Mont(BN_C2, BN_C2, BN_R2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModMul_Mont(BN_C3, BN_C1, BN_C2, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_ModMul_Mont(BN_C3, BN_C3, BN_One, BN_N2, wModuleConst, 2*iBNWordLen);
	BN_GetLastRes(BN_C3, BN_N2, 2*iBNWordLen);
	result = BNToByte(BN_C3, 2*iBNWordLen, pbBN_Result, &len);
}


//////Add by PC 2018.11.12
/*
功能：paillier同态乘法, c^* = E(m1)^m2 mod n^2
输入：加密密文c1,明文m2, 公钥n
输出：新密文
*/
void PAI_HomMul(U8 *pbBN_Result, U8 *pbBN_c1, U8 *pbBN_m2, S32 iM2_Len, U8 *pbBN_n, S32 iBNWordLen)
{
	/****************************/
	U32 BN_N2[BNMAXWordLen];
	U32 BN_N[BNMAXWordLen];
	U32 BN_R[BNMAXWordLen];
	U32 BN_R2[BNMAXWordLen];
	U32 BN_C1[BNMAXWordLen];
	U32 BN_M2[BNMAXWordLen];
	U32 BN_C3[BNMAXWordLen];
	U32 BN_One[BNMAXWordLen];
	U32 wModuleConst = 0;

	U8 bBN_T[8*BNMAXWordLen] = {0};
	S32 i = 0;
	S32 len = 0;
	S32 loglen = 0;
	S32 result = 0;
	/****************************/
	BN_Reset(BN_N2, BNMAXWordLen);
	BN_Reset(BN_N, BNMAXWordLen);
	BN_Reset(BN_R, BNMAXWordLen);
	BN_Reset(BN_R2, BNMAXWordLen);
	BN_Reset(BN_C1, BNMAXWordLen);
	BN_Reset(BN_M2, BNMAXWordLen);
	BN_Reset(BN_C3, BNMAXWordLen);
	BN_Reset(BN_One, BNMAXWordLen);
	BN_One[0] = LSBOfWord;

	result = ByteToBN(pbBN_n, 4*iBNWordLen, BN_N, iBNWordLen);
	result = ByteToBN(pbBN_c1, 8*iBNWordLen, BN_C1, 2*iBNWordLen);
	result = ByteToBN(pbBN_m2, iM2_Len, BN_M2, iM2_Len / 4);

	//Prepare Montgomery Mul with n^2
	BN_Mul(BN_N2, BN_N, BN_N, iBNWordLen);
	wModuleConst = BN_GetMontConst(BN_N2[0], 32);
	BN_GetR(BN_R, BN_N2, 2*iBNWordLen);
	loglen = (S32)(log(iBNWordLen*2*32)/log(2));
	BN_GetR2(BN_R2, BN_R, BN_N2, wModuleConst, 2*iBNWordLen, loglen);
	BN_GetLastRes(BN_R2, BN_N2, 2*iBNWordLen);

	//C3 = C1 ^ M2 mod n^2
	BN_ModMul_Mont(BN_C1, BN_C1, BN_R2, BN_N2, wModuleConst, 2 * iBNWordLen);
	BN_ModExp(BN_C3, BN_C1, BN_M2, BN_N2, wModuleConst, 2 * iBNWordLen);
	BN_ModMul_Mont(BN_C3, BN_C3, BN_One, BN_N2, wModuleConst, 2 * iBNWordLen);
	BN_GetLastRes(BN_C3, BN_N2, 2*iBNWordLen);
	result = BNToByte(BN_C3, 2*iBNWordLen, pbBN_Result, &len);
}
