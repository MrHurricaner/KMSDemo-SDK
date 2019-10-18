#include "ecdsa.h"

#include "secp256k1_curve.h"
#include "secp256k1_fp_ecp.h"
#include "common.h"

#define ECDSA_STATIC

/*Define of maximum curve size of support */
#define ECDSA_MAX_BITS			256
#define ECDSA_MAX_BYTES			(ECDSA_MAX_BITS/8)
#define ECDSA_MAX_WORDS			(ECDSA_MAX_BYTES/4)

/*Define of current curve size of support */
#ifdef ECDSA_STATIC
#define ECDSA_CUR_BITS			256
#define ECDSA_CUR_BYTES			(ECDSA_CUR_BITS/8)
#define ECDSA_CUR_WORDS			(ECDSA_CUR_BYTES/4)
#else
#define ECDSA_CUR_BITS			(pSys_Para->iBNWordLen*32)
#define ECDSA_CUR_BYTES			(pSys_Para->iBNWordLen*4)
#define ECDSA_CUR_WORDS			(pSys_Para->iBNWordLen)
#endif

//SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
//static SECP256K1_Sys_Para *pSys_Para = NULL;

/*
=======================================================================================================================
	描述: 产生密钥对
	输入:
		 pSys_Para:				椭圆曲线系统参数
		 pbPriKey:			    用户私钥
	输出:
		 pbPubKey:			    用户公钥
=======================================================================================================================
*/

S32 ECDSA_KeyGen(U8 *pbPubKey, SECP256K1_Sys_Para * pSys_Para, U8 *pbPriKey)
{
	SECP256K1_Fp_ECP_A Ap;
	U32	d[ECDSA_MAX_WORDS];
	S32 bytelen;

	//Input transform
	if (pSys_Para == NULL)
	{
		//SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, BNWordLen);
		//pSys_Para = &m_SECP256K1_Sys_Para;
		return 0;
	}
	ByteToBN(pbPriKey, ECDSA_CUR_BYTES, d, ECDSA_CUR_WORDS);

	SECP256K1_Fp_ECP_KP(&Ap, &pSys_Para->EC_Fp_G_Mont, d, pSys_Para);

	//Output transform
	BN_ModMul_Mont(Ap.X, Ap.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Ap.Y, Ap.Y, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Ap.X, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Ap.Y, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BNToByte(Ap.X, ECDSA_CUR_WORDS, pbPubKey, &bytelen);
	BNToByte(Ap.Y, ECDSA_CUR_WORDS, pbPubKey + ECDSA_CUR_BYTES, &bytelen);

	return 1;
}

/*
=======================================================================================================================
	描述:ECDSA签名算法
	输入:
		pbHash:杂凑值，即待签名数据的杂凑值,长度为32字节
		pbPriKey:私钥，即签名所用的私钥,长度为32字节
		pbRand:随机数，即签名所用的随机数,长度为32字节
		pSys_Para: 系统参数
	输出:
		pbSign:签名值,即(r,s)，长度为64字节
	返回：
		0	失败
		1	成功
=======================================================================================================================
*/
S32 ECDSA_Sign(U8 *pbSign, SECP256K1_Sys_Para * pSys_Para, U8 *pbHash, U8 *pbPriKey, U8 *pbRand)
{
	SECP256K1_Fp_ECP_A Ap;
	U32	d[ECDSA_MAX_WORDS], z[ECDSA_MAX_WORDS], k[ECDSA_MAX_WORDS], *r, *s;
	S32 bytelen;

	//Input transform
	if (pSys_Para == NULL)
	{
		return 0;
		//SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, BNWordLen);
		//pSys_Para = &m_SECP256K1_Sys_Para;
	}
	ByteToBN(pbPriKey, ECDSA_CUR_BYTES, d, ECDSA_CUR_WORDS);
	ByteToBN(pbRand, ECDSA_CUR_BYTES, k, ECDSA_CUR_WORDS);
	ByteToBN(pbHash, ECDSA_CUR_BYTES, z, ECDSA_CUR_WORDS);
	r = Ap.X;
	s = z;

	//(x1,y1) = [k]G; 
	SECP256K1_Fp_ECP_KP(&Ap, &pSys_Para->EC_Fp_G_Mont, k, pSys_Para);
	//r = x1; If r == 0 mod N, err
	BN_ModMul_Mont(r, Ap.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(r, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	if (BN_IsZero(r, pSys_Para->iBNWordLen))
		return 0;
	//s = k ^ -1 * (z + r * d) mod N; If s == 0 mod N, err
	BN_ModMul_Mont(d, r, d, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*d*R^-1
	BN_ModMul_Mont(d, d, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*d
	BN_ModAdd(d, d, z, pSys_Para->EC_N, pSys_Para->iBNWordLen);//z+r*d
	BN_GetInv_Mont(k, k, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->EC_RR_N, pSys_Para->iBNWordLen);//k^-1*R
	BN_ModMul_Mont(s, k, d, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//k^-1 * (z + r * d)
	BN_GetLastRes(s, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	if (BN_IsZero(s, pSys_Para->iBNWordLen))
		return 0;

	//Output transform
	BNToByte(r, ECDSA_CUR_WORDS, pbSign, &bytelen);
	BNToByte(s, ECDSA_CUR_WORDS, pbSign + ECDSA_CUR_BYTES, &bytelen);

	return 1;
}

/*
=======================================================================================================================
	描述:ECDSA验签算法
	输入:
		pbHash:杂凑值，即待验签数据的杂凑值,长度为32字节
		pbPubKey:公钥，即验签所用的公钥,长度为64字节
		pbSign:签名值,即待验证的签名值(r,s)，长度为64字节
		pSys_Para: 系统参数
	输出:
		无
	返回：
		0	失败
		1	成功
=======================================================================================================================
*/
S32 ECDSA_Verify(SECP256K1_Sys_Para * pSys_Para, U8 *pbHash, U8 *pbPubKey, U8 *pbSign)
{
	SECP256K1_Fp_ECP_A Ap, Bp;
	SECP256K1_Fp_ECP_J Jp;
	U32	r[ECDSA_MAX_WORDS], s[ECDSA_MAX_WORDS], z[ECDSA_MAX_WORDS], *u1, *u2;

	//Input transform
	if (pSys_Para == NULL)
	{
		//SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, BNWordLen);
		//pSys_Para = &m_SECP256K1_Sys_Para;
		return 0;
	}
	ByteToBN(pbHash, ECDSA_CUR_BYTES, z, ECDSA_CUR_WORDS);
	ByteToBN(pbSign, ECDSA_CUR_BYTES, r, ECDSA_CUR_WORDS);
	ByteToBN(pbSign + ECDSA_CUR_BYTES, ECDSA_CUR_BYTES, s, ECDSA_CUR_WORDS);
	u1 = z; u2 = s;
	ByteToBN(pbPubKey, ECDSA_CUR_BYTES, Bp.X, ECDSA_CUR_WORDS);
	ByteToBN(pbPubKey + ECDSA_CUR_BYTES, ECDSA_CUR_BYTES, Bp.Y, ECDSA_CUR_WORDS);
	BN_ModMul_Mont(Bp.X, Bp.X, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Bp.Y, Bp.Y, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);

	//All steps
	BN_GetInv_Mont(s, s, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->EC_RR_N, pSys_Para->iBNWordLen);//s^-1*R
	BN_ModMul_Mont(u1, z, s, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//z*s^-1
	BN_ModMul_Mont(u2, r, s, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*s^-1
	SECP256K1_Fp_ECP_KP(&Ap, &pSys_Para->EC_Fp_G_Mont, u1, pSys_Para);//[u1]G
	SECP256K1_Fp_ECP_KP(&Bp, &Bp, u2, pSys_Para);//[u2]Qa
	SECP256K1_Fp_ECP_AToJ(&Jp, &Ap, pSys_Para);
	SECP256K1_Fp_ECP_JAddAToJ(&Jp, &Jp, &Bp, pSys_Para);
	SECP256K1_Fp_ECP_JToA(&Ap, &Jp, pSys_Para);//[u1]G+[u2]Qa
	BN_ModMul_Mont(Ap.X, Ap.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Ap.X, pSys_Para->EC_N, pSys_Para->iBNWordLen);

	//Check r = x1 mod N
	if (BN_IsZero(Ap.X, pSys_Para->iBNWordLen))
		return 0;
	if (BN_JE(r, Ap.X, pSys_Para->iBNWordLen))
		return 1;
	return 0;
}