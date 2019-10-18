#include "common.h"
#include "secp256k1_curve.h"
#include "secp256k1_fp_ecp.h"
#include "ecschnorr.h"
#include "ecdsa.h"
#include "pailler.h"
#include "sha2.h"

/*
=======================================================================================================================
	描述:ECDSA两方协同签名——乘法器函数
	使用流程:
				P1																P2
	ECDSA_DiCo_Multiplier_Pre(sk,pk)
	ECDSA_DiCo_Multiplier_C1(a,pk)
									--------C1,pk------>
															ECDSA_DiCo_Multiplier_C2_and_Beta(b,pk)
									<--------C2---------
	ECDSA_DiCo_Multiplier_Alpha(sk)
			(a, alpha)														(b, beta)
	备注：
		a * b = alpha + beta

	sk = lambda || mu || n
	pk = n || g
=======================================================================================================================
*/

#define ECDSA_DICO_MULT_WordLen		32

//Input: iBNWordLen	(32)
//Output: pk(128B)=(n) sk(384B)=(r,u,n)
void ECDSA_DiCo_Multiplier_Pre(U8 *pbPK, U8 *pbSK, S32 iBNWordLen)
{
	U8 *pbBN_n, *pbBN_g, *pbBN_lambda, *pbBN_mu;
	int i;

	pbBN_g = pbPK;
	pbBN_lambda = pbSK;
	pbBN_mu = pbSK + iBNWordLen * 4;
	pbBN_n = pbSK + iBNWordLen * 8;

	PAI_KeyGen(pbBN_n, pbBN_g, pbBN_lambda, pbBN_mu, iBNWordLen / 2);
	for (i = 0; i < iBNWordLen * 4; i++)
	{
		pbPK[i] = pbBN_n[i];
	}
}

//Input: a(32B) pk(128B) rnd(128B) iBNWordLen(32W = 128B)
//Output: C1(256B)
void ECDSA_DiCo_Multiplier_C1(U8 *pbBN_C1,
	U8 *pbBN_a, U32 *pwMod, S32 iModWordLen, 
	U8 *pbPK, U8 *pbRand, S32 iBNWordLen)
{
	U8 *pbBN_n, pbBN_g[BNMAXWordLen*4];
	U32 c;
	int i;

	//Get (n, g)
	pbBN_n = pbPK;
	c = 1;
	for (i = iBNWordLen * 4 - 1; i >= 0; i--)
	{
		c += (U32)pbBN_n[i];
		pbBN_g[i] = (U8)c;
		c >>= 8;
	}

	//C1 = E(a)
	PAI_Encryption(pbBN_C1, pbBN_a, iModWordLen * 4, pbBN_n, pbBN_g, pbRand, iBNWordLen * 4, iBNWordLen);
}

//Input: b(32B) mod(32B) iModWordLen(8W = 32B) C1(256B) pk(128B) rnd(160B) iBNWordLen(32W = 128B)
//Output: C2(256B) beta(32B)
void ECDSA_DiCo_Multiplier_C2_and_Beta(U8 *pbBN_C2, U8 *pbBN_beta,
	U8 *pbBN_b, U32 *pwMod, S32 iModWordLen,
	U8 *pbBN_C1,U8 *pbPK, U8 *pbRand, S32 iBNWordLen)
{
	U8 pbBN_T[BNMAXWordLen * 4];
	U32 pwBN_Beta[BNWordLen];
	S32 bytelen;
	U8 *pbBN_n, pbBN_g[BNMAXWordLen * 4];
	U32 c;
	int i;

	//Get (n, g)
	pbBN_n = pbPK;
	c = 1;
	for (i = iBNWordLen * 4 - 1; i >= 0; i--)
	{
		c += (U32)pbBN_n[i];
		pbBN_g[i] = (U8)c;
		c >>= 8;
	}

	//C2 = C1 ^ b * E(beta')
	PAI_HomMul(pbBN_C2, pbBN_C1, pbBN_b, iModWordLen * 4, pbBN_n, iBNWordLen);
	PAI_Encryption(pbBN_T, pbRand + iBNWordLen * 4, iModWordLen * 4, pbBN_n, pbBN_g, pbRand, iBNWordLen * 4, iBNWordLen);
	PAI_HomAdd(pbBN_C2, pbBN_C2, pbBN_T, pbBN_n, iBNWordLen);

	//beta = -beta' mod q
	ByteToBN(pbRand + iBNWordLen * 4, iModWordLen * 4, pwBN_Beta, iModWordLen);
	BN_ModSub(pwBN_Beta, pwMod, pwBN_Beta, pwMod, iModWordLen);
	BNToByte(pwBN_Beta, iModWordLen, pbBN_beta, &bytelen);
}

void ECDSA_DiCo_Multiplier_Alpha(U8 *pbBN_alpha,
	U32 *pwMod, S32 iModWordLen,
	U8 *pbBN_C2, U8 *pbSK, S32 iBNWordLen)
{
	U8 pbBN_m[PaiBNWordLen * 4];
	U32 pwBN_m[BNMAXWordLen], pwBN_r[PaiBNWordLen];
	S32 bytelen;
	U8 *pbBN_n, *pbBN_lambda, *pbBN_mu;

	pbBN_lambda = pbSK;
	pbBN_mu = pbSK + iBNWordLen * 4;
	pbBN_n = pbSK + iBNWordLen * 8;

	//m = D(C2)
	PAI_Decryption(pbBN_m, pbBN_C2, pbBN_n, pbBN_lambda, pbBN_mu, iBNWordLen);

	//alpha = m mod q
	BN_Reset(pwBN_m, BNMAXWordLen);//！！！！不可省略
	ByteToBN(pbBN_m, iBNWordLen * 4, pwBN_m, iBNWordLen);
	BN_Mod_Basic(pwBN_r, iModWordLen, pwBN_m, iBNWordLen, pwMod, iModWordLen);
	BNToByte(pwBN_r, iModWordLen, pbBN_alpha, &bytelen);
}

/*
=======================================================================================================================

=======================================================================================================================
*/


/*
=======================================================================================================================
	描述:ECDSA两方协同签名——密钥生成算法——设置秘密值
	输入:
		pSys_Para: 系统参数
		pbMultPK: 乘法器公钥，长度128字节
		pbPartSK: 部分私钥，长度为32字节
		pbRand：计算所需的随机数，长度为32字节
	输出:
		pbPartPK: 部分公钥,即椭圆曲线点，长度为64字节
		pbZKProof: 零知识证明信息，长度为64字节
	返回：
		0	失败
		1	成功
=======================================================================================================================
*/
S32 ECDSA_DiCo_KeyGen_SetPri(U8 *pbA1, U8 *pbZK, SECP256K1_Sys_Para * pSys_Para, U8 *pbPK, U8 *pbX1, U8 *pbRand)
{
	sha256_context ctx;
	U8 pbG[2 * BNByteLen], pbM[BNByteLen];

	//A1 = [x1]G
	ECDSA_KeyGen(pbA1, pSys_Para, pbX1);

	SECP256K1_Fp_ECP_AToByte(pbG, pSys_Para, &pSys_Para->EC_Fp_G_Mont);

	//M = H( G || A || pk )
	sha256_starts(&ctx);
	sha256_update(&ctx, pbG, pSys_Para->iBNWordLen * 8);
	sha256_update(&ctx, pbA1, pSys_Para->iBNWordLen * 8);
	if (pbPK)
	{
		sha256_update(&ctx, pbPK, ECDSA_DICO_MULT_WordLen * 4);
	}
	sha256_finish(&ctx, pbM);

	//ZK Proof
	ECSchnorr_Sign(pbZK, pSys_Para, pbM, pbX1, pbRand);

	return 1;
}

/*
=======================================================================================================================
	描述:ECDSA两方协同签名——密钥生成算法——得到公钥
	输入:
		pSys_Para: 系统参数
		pbMultPK: 乘法器公钥，长度128字节
		pbPartSK: 己方的部分私钥，长度为32字节
		pbPartPK：己方的部分公钥，长度为64字节
		pbOtherPK：对方的部分公钥，长度为64字节
		pbZKProof：对方的零知识证明，长度为64字节
	输出:
		pbPubKey: 公钥,即椭圆曲线点，长度为64字节
	返回：
		0	失败
		1	成功
=======================================================================================================================
*/
S32 ECDSA_DiCo_KeyGen_GetPub(U8 *pbPubKey, SECP256K1_Sys_Para * pSys_Para, U8 *pbPK, U8 *pbX1, U8 *pbA1, U8 *pbA2, U8 *pbPi2)
{
	SECP256K1_Fp_ECP_A Yp;
	SECP256K1_Fp_ECP_J Jp;
	sha256_context ctx;
	U8 pbG[2 * BNByteLen], pbM[BNByteLen];
	S32 bytelen;
	int ret;

	SECP256K1_Fp_ECP_AToByte(pbG, pSys_Para, &pSys_Para->EC_Fp_G_Mont);

	//M = H( G || A || pk )
	sha256_starts(&ctx);
	sha256_update(&ctx, pbG, pSys_Para->iBNWordLen * 8);
	sha256_update(&ctx, pbA2, pSys_Para->iBNWordLen * 8);
	if (pbPK)
	{
		sha256_update(&ctx, pbPK, ECDSA_DICO_MULT_WordLen * 4);
	}
	sha256_finish(&ctx, pbM);

	//ZK Vefiry
	ret = ECSchnorr_Verify(pSys_Para, pbM, pbA2, pbPi2);
	if (ret != 1)
		return 0;//ZK Vefiry invaild
	
	//A1+A2
	SECP256K1_Fp_ECP_ByteToA(&Yp, pSys_Para, pbA1);
	//ByteToBN(pbA1, BNByteLen, Yp.X, BNWordLen);
	//ByteToBN(pbA1 + BNByteLen, BNByteLen, Yp.Y, BNWordLen);
	//BN_ModMul_Mont(Yp.X, Yp.X, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	//BN_ModMul_Mont(Yp.Y, Yp.Y, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	SECP256K1_Fp_ECP_AToJ(&Jp, &Yp, pSys_Para);

	SECP256K1_Fp_ECP_ByteToA(&Yp, pSys_Para, pbA2);
	//ByteToBN(pbA2, BNByteLen, Yp.X, BNWordLen);
	//ByteToBN(pbA2 + BNByteLen, BNByteLen, Yp.Y, BNWordLen);
	//BN_ModMul_Mont(Yp.X, Yp.X, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	//BN_ModMul_Mont(Yp.Y, Yp.Y, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	SECP256K1_Fp_ECP_JAddAToJ(&Jp, &Jp, &Yp, pSys_Para);

	SECP256K1_Fp_ECP_JToA(&Yp, &Jp, pSys_Para);
	BN_ModMul_Mont(Yp.X, Yp.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Yp.Y, Yp.Y, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Yp.X, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Yp.Y, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BNToByte(Yp.X, BNWordLen, pbPubKey, &bytelen);
	BNToByte(Yp.Y, BNWordLen, pbPubKey + BNByteLen, &bytelen);

	return 1;
}

/*
=======================================================================================================================

=======================================================================================================================
*/

S32 ECDSA_DiCo_KeyGen_P1_Send(U8 *pbMultSK, U8 *pbMultPK, U8 *pbP1_PK, U8 *pbP1_ZK, SECP256K1_Sys_Para * pSys_Para,
	U8 *pbP1_SK, U8 *pbRand)
{
	int ret;

	//Prepare for Multiplier
	ECDSA_DiCo_Multiplier_Pre(pbMultPK, pbMultSK, ECDSA_DICO_MULT_WordLen);

	//P1 set prikey
	ret = ECDSA_DiCo_KeyGen_SetPri(pbP1_PK, pbP1_ZK, pSys_Para, pbMultPK, pbP1_SK, pbRand);
	if (ret != 1)
		return ret;

	return 1;
}

S32 ECDSA_DiCo_KeyGen_P2_Done(U8 *pbPubKey, U8 *pbP2_PK, U8 *pbP2_ZK, SECP256K1_Sys_Para * pSys_Para,
	U8 *pbMultPK, U8 *pbP2_SK, U8 *pbP1_PK, U8 *pbP1_ZK, U8 *pbRand)
{
	int ret;

	//P2 set prikey
	ret = ECDSA_DiCo_KeyGen_SetPri(pbP2_PK, pbP2_ZK, pSys_Para, pbMultPK, pbP2_SK, pbRand);
	if (ret != 1)
		return ret;

	//P2 verify P1 ZkProof
	ret = ECDSA_DiCo_KeyGen_GetPub(pbPubKey, pSys_Para, pbMultPK, pbP2_SK, pbP2_PK, pbP1_PK, pbP1_ZK);
	if (ret != 1)
		return ret;

	return 1;
}

S32 ECDSA_DiCo_KeyGen_P1_Recv(U8 *pbPubKey, SECP256K1_Sys_Para * pSys_Para,
	U8 *pbMultPK, U8 *pbP1_SK, U8 *pbP1_PK, U8 *pbP2_PK, U8 *pbP2_ZK)
{
	int ret;

	//P1 verify P2 ZkProof
	ret = ECDSA_DiCo_KeyGen_GetPub(pbPubKey, pSys_Para, pbMultPK, pbP1_SK, pbP1_PK, pbP2_PK, pbP2_ZK);
	if (ret != 1)
		return ret;

	return 1;
}


S32 ECDSA_DiCo_Sign_Part1_SetR(U8 *pbEC_R1, U8 *pbZK_P1, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_k1, U8 *pbRand)
{
	return ECDSA_DiCo_KeyGen_SetPri(pbEC_R1, pbZK_P1, pSys_Para, NULL, pbBN_k1, pbRand);
}

S32 ECDSA_DiCo_Sign_Part1_GetR(U8 *pbBN_r, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_k1, U8 *pbEC_R1, U8 *pbEC_R2, U8 *pbZK_P2)
{
	U8 pbEC_R[2*BNByteLen];
	int i;
	int ret;
	
	ret = ECDSA_DiCo_KeyGen_GetPub(pbEC_R, pSys_Para, NULL, pbBN_k1, pbEC_R1, pbEC_R2, pbZK_P2);
	if (ret != 1)
		return ret;
	for (i = 0; i < pSys_Para->iBNWordLen * 4; i++)
	{
		pbBN_r[i] = pbEC_R[i];
	}
	return 1;
}

//计算delta1 = r*x + e/2 mod n，e/2 的处理根据e的奇偶性决定
static void ECDSA_DiCo_Sign_GetDelta1(U8 *pbBN_delta1, SECP256K1_Sys_Para *pSys_Para, U8 *pbBN_e, U8 *pbBN_r, U8 *pbBN_x)
{
	U32 pwBN_r[BNWordLen], pwBN_x[BNWordLen], pwBN_e[BNWordLen];
	S32 bytelen;

	//Get r, e and x, compute delta1 = r*x + e/2 mod n
	ByteToBN(pbBN_r, pSys_Para->iBNWordLen * 4, pwBN_r, pSys_Para->iBNWordLen);
	ByteToBN(pbBN_x, pSys_Para->iBNWordLen * 4, pwBN_x, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(pwBN_x, pwBN_r, pwBN_x, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*x*R^-1
	BN_ModMul_Mont(pwBN_x, pwBN_x, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*x
	ByteToBN(pbBN_e, pSys_Para->iBNWordLen * 4, pwBN_e, pSys_Para->iBNWordLen);
	if (pwBN_e[0] & 1)
	{//如果e是奇数，delta1=r*x + e - r
		BN_ModSub(pwBN_x, pwBN_x, pwBN_r, pSys_Para->EC_N, pSys_Para->iBNWordLen);
		BN_ModAdd(pwBN_x, pwBN_x, pwBN_e, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	}
	else
	{//如果e是偶数，delta1=r*x + e>>1
		BN_ShiftRightOneBit(pwBN_e, pSys_Para->iBNWordLen);
		BN_ModAdd(pwBN_x, pwBN_x, pwBN_e, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	}
	BN_GetLastRes(pwBN_x, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(pwBN_x, pSys_Para->iBNWordLen, pbBN_delta1, &bytelen);//Out delta1 to byte
}

//计算delta2 = r*x + e/2 mod n，e/2 的处理根据e的奇偶性决定
static void ECDSA_DiCo_Sign_GetDelta2(U8 *pbBN_delta2, SECP256K1_Sys_Para *pSys_Para, U8 *pbBN_e, U8 *pbBN_r, U8 *pbBN_x)
{
	U32 pwBN_r[BNWordLen], pwBN_x[BNWordLen], pwBN_e[BNWordLen];
	S32 bytelen;

	//Get r, e and x, compute delta2 = r*x + e/2 mod n
	ByteToBN(pbBN_r, pSys_Para->iBNWordLen * 4, pwBN_r, pSys_Para->iBNWordLen);
	ByteToBN(pbBN_x, pSys_Para->iBNWordLen * 4, pwBN_x, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(pwBN_x, pwBN_r, pwBN_x, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*x*R^-1
	BN_ModMul_Mont(pwBN_x, pwBN_x, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//r*x
	ByteToBN(pbBN_e, pSys_Para->iBNWordLen * 4, pwBN_e, pSys_Para->iBNWordLen);
	if (pwBN_e[0] & 1)
	{//如果e是奇数，delta2=r*x + r
		BN_ModAdd(pwBN_x, pwBN_x, pwBN_r, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	}
	else
	{//如果e是偶数，delta2=r*x + e>>1
		BN_ShiftRightOneBit(pwBN_e, pSys_Para->iBNWordLen);
		BN_ModAdd(pwBN_x, pwBN_x, pwBN_e, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	}
	BN_GetLastRes(pwBN_x, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(pwBN_x, pSys_Para->iBNWordLen, pbBN_delta2, &bytelen);//Out delta1 to byte
}


S32 ECDSA_DiCo_Sign_Part2_Send(
	U8 *pbMP_ByP1,
	U8 *pbMP_ToP2,
	SECP256K1_Sys_Para * pSys_Para,
	U8 *pbBN_e,
	U8 *pbBN_r,
	U8 *pbBN_x1,
	U8 *pbBN_k1,
	U8 *pbBN_p1,
	U8 *pbMultPK,
	U8 *pbRand
	)
{
	U32 bn_T[BNWordLen], bn_A[BNWordLen], bn_B[BNWordLen];
	U8 pbBN_d1[BNByteLen];
	S32 bytelen;
	S32 iPaiWordLen = 32;
	U8 *pbBN_C1, *pbBN_R1;
	U8 *pbBN_k1p1;
	U8 *pbBN_p1d1;

	//pbMP_ByP1 = k1*p1 || p1*d1
	pbBN_k1p1 = pbMP_ByP1;
	pbBN_p1d1 = pbMP_ByP1 + pSys_Para->iBNWordLen * 4;

	//pbMP_ToP2 = C1 || C1 || C1 || C1
	pbBN_C1 = pbMP_ToP2;

	//pbRand = R1 || R1 || R1 || R1
	pbBN_R1 = pbRand;

	//Get r, e and x1, compute delta1 = r*x + e/2 mod n
	ECDSA_DiCo_Sign_GetDelta1(pbBN_d1, pSys_Para, pbBN_e, pbBN_r, pbBN_x1);

	//Get p1, k1, d1
	ByteToBN(pbBN_p1, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);//Get p1 to T
	ByteToBN(pbBN_k1, pSys_Para->iBNWordLen * 4, bn_A, pSys_Para->iBNWordLen);//Get k1 to A
	ByteToBN(pbBN_d1, pSys_Para->iBNWordLen * 4, bn_B, pSys_Para->iBNWordLen);//Get d1 to B

	//alpha1 = p1*k1
	BN_ModMul_Mont(bn_A, bn_T, bn_A, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p1 * d1 * R^-1
	BN_ModMul_Mont(bn_A, bn_A, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p1 * delta1
	
	//beta1 = p1*d1
	BN_ModMul_Mont(bn_B, bn_T, bn_B, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p1 * d1 * R^-1
	BN_ModMul_Mont(bn_B, bn_B, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p1 * delta1
	
	//Multiplier-1:(k1, p2), input k1
	ECDSA_DiCo_Multiplier_C1(pbBN_C1, pbBN_k1, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbMultPK, pbRand, iPaiWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_R1 += iPaiWordLen * 4;
	//Multiplier-2:(k2, p2), input p1
	ECDSA_DiCo_Multiplier_C1(pbBN_C1, pbBN_p1, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbMultPK, pbRand, iPaiWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_R1 += iPaiWordLen * 4;
	//Multiplier-3:(d1, p2), input d1
	ECDSA_DiCo_Multiplier_C1(pbBN_C1, pbBN_d1, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbMultPK, pbRand, iPaiWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_R1 += iPaiWordLen * 4;
	//Multiplier-4:(d2, p2), input p1
	ECDSA_DiCo_Multiplier_C1(pbBN_C1, pbBN_p1, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbMultPK, pbRand, iPaiWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_R1 += iPaiWordLen * 4;

	//Output alpha1 and beta1
	BN_GetLastRes(bn_A, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BN_GetLastRes(bn_B, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(bn_A, pSys_Para->iBNWordLen, pbBN_k1p1, &bytelen);
	BNToByte(bn_B, pSys_Para->iBNWordLen, pbBN_p1d1, &bytelen);

	return 1;
}


S32 ECDSA_DiCo_Sign_Part2_Mult(
	U8 *pbMP_ToP1,
	U8 *pbBN_alpha2,
	U8 *pbBN_beta2,
	SECP256K1_Sys_Para * pSys_Para,
	U8 *pbBN_e,
	U8 *pbBN_r,
	U8 *pbBN_x2,
	U8 *pbBN_k2,
	U8 *pbBN_p2,
	U8 *pbMultPK,
	U8 *pbMP_ToP2,
	U8 *pbRand
	)
{
	U32 bn_T[BNWordLen], bn_B[BNWordLen], bn_A[BNWordLen];
	U8 pbBN_d2[BNByteLen], pbTmp[BNByteLen];
	U8 *pbBN_C1, *pbBN_C2, *pbBN_R2;
	S32 iPaiWordLen = 32;
	S32 bytelen;

	//pbMP_ToP1 = C2 || C2 || C2 || C2
	pbBN_C2 = pbMP_ToP1;

	//pk || C1 || C1 || C1 || C1
	pbBN_C1 = pbMP_ToP2;

	//R2 || R2 || R2 || R2
	pbBN_R2 = pbRand;

	//Get r, e and x, compute delta1 = r*x + e/2 mod n
	ECDSA_DiCo_Sign_GetDelta2(pbBN_d2, pSys_Para, pbBN_e, pbBN_r, pbBN_x2);

	//Get p2, k2, d2
	ByteToBN(pbBN_p2, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);//Get p2 to T
	ByteToBN(pbBN_k2, pSys_Para->iBNWordLen * 4, bn_A, pSys_Para->iBNWordLen);//Get k2 to A
	ByteToBN(pbBN_d2, pSys_Para->iBNWordLen * 4, bn_B, pSys_Para->iBNWordLen);//Get d2 to B

	//alpha1 = p2*k2
	BN_ModMul_Mont(bn_A, bn_T, bn_A, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p2 * k21 * R^-1
	BN_ModMul_Mont(bn_A, bn_A, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//A = p2 * k2

	//beta1 = p2*d2
	BN_ModMul_Mont(bn_B, bn_T, bn_B, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//p2 * d2 * R^-1
	BN_ModMul_Mont(bn_B, bn_B, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);//B = p2 * d2

	//Multiplier-1:(k1, p2), input p2, get k1*p2
	ECDSA_DiCo_Multiplier_C2_and_Beta(pbBN_C2, pbTmp, pbBN_p2, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C1, pbMultPK, pbBN_R2, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_A, bn_A, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_C2 += iPaiWordLen * 8;
	pbBN_R2 += (iPaiWordLen + pSys_Para->iBNWordLen) * 4;

	//Multiplier-2:(k2, p1), input k2, get k2*p1
	ECDSA_DiCo_Multiplier_C2_and_Beta(pbBN_C2, pbTmp, pbBN_k2, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C1, pbMultPK, pbBN_R2, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_A, bn_A, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_C2 += iPaiWordLen * 8;
	pbBN_R2 += (iPaiWordLen + pSys_Para->iBNWordLen) * 4;

	//Multiplier-3:(d1, p2), input p2, get d1*p2
	ECDSA_DiCo_Multiplier_C2_and_Beta(pbBN_C2, pbTmp, pbBN_p2, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C1, pbMultPK, pbBN_R2, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_B, bn_B, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_C2 += iPaiWordLen * 8;
	pbBN_R2 += (iPaiWordLen + pSys_Para->iBNWordLen) * 4;

	//Multiplier-4:(d2, p1), input d2, get d2*p1
	ECDSA_DiCo_Multiplier_C2_and_Beta(pbBN_C2, pbTmp, pbBN_d2, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C1, pbMultPK, pbBN_R2, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_B, bn_B, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C1 += iPaiWordLen * 8;
	pbBN_C2 += iPaiWordLen * 8;
	pbBN_R2 += (iPaiWordLen + pSys_Para->iBNWordLen) * 4;

	//Output alpha2 and beta2
	BN_GetLastRes(bn_A, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BN_GetLastRes(bn_B, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(bn_A, pSys_Para->iBNWordLen, pbBN_alpha2, &bytelen);
	BNToByte(bn_B, pSys_Para->iBNWordLen, pbBN_beta2, &bytelen);

	return 1;
}


S32 ECDSA_DiCo_Sign_Part2_Recv(
	U8 *pbBN_alpha1,
	U8 *pbBN_beta1,
	SECP256K1_Sys_Para * pSys_Para,
	U8 *pbMultSK,
	U8 *pbMP_ByP1,
	U8 *pbMP_ToP1
	)
{
	S32 iPaiWordLen = 32;
	S32 bytelen;
	U8 pbTmp[BNWordLen * 4];
	U32 bn_A[BNWordLen], bn_B[BNWordLen], pwBN_T[BNWordLen];

	U8 *pbBN_C2, *pbBN_A, *pbBN_B;

	//k1*p1 || p1*d1
	pbBN_A = pbMP_ByP1;
	pbBN_B = pbMP_ByP1 + pSys_Para->iBNWordLen * 4;

	//C2 || C2 || C2 || C2
	pbBN_C2 = pbMP_ToP1;

	ByteToBN(pbBN_A, pSys_Para->iBNWordLen * 4, bn_A, pSys_Para->iBNWordLen);
	ByteToBN(pbBN_B, pSys_Para->iBNWordLen * 4, bn_B, pSys_Para->iBNWordLen);

	//Multiplier-1:(k1, p2), get k1*p2
	ECDSA_DiCo_Multiplier_Alpha(pbTmp, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C2, pbMultSK, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, pwBN_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_A, bn_A, pwBN_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C2 += iPaiWordLen * 8;

	//Multiplier-2:(k2, p1), get k2*p1
	ECDSA_DiCo_Multiplier_Alpha(pbTmp, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C2, pbMultSK, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, pwBN_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_A, bn_A, pwBN_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C2 += iPaiWordLen * 8;

	//Multiplier-3:(d1, p2), get d1*p2
	ECDSA_DiCo_Multiplier_Alpha(pbTmp, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C2, pbMultSK, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, pwBN_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_B, bn_B, pwBN_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C2 += iPaiWordLen * 8;

	//Multiplier-4:(d2, p1),  get d2*p1
	ECDSA_DiCo_Multiplier_Alpha(pbTmp, pSys_Para->EC_N, pSys_Para->iBNWordLen, pbBN_C2, pbMultSK, iPaiWordLen);
	ByteToBN(pbTmp, pSys_Para->iBNWordLen * 4, pwBN_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_B, bn_B, pwBN_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	pbBN_C2 += iPaiWordLen * 8;

	//Output alpha1 and beta1
	BN_GetLastRes(bn_A, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BN_GetLastRes(bn_B, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(bn_A, pSys_Para->iBNWordLen, pbBN_alpha1, &bytelen);
	BNToByte(bn_B, pSys_Para->iBNWordLen, pbBN_beta1, &bytelen);

	return 1;
}

S32 ECDSA_DiCo_Sign_Part2_GetS(
	U8 *pbBN_s,
	SECP256K1_Sys_Para * pSys_Para,
	U8 *pbBN_alpha1,
	U8 *pbBN_beta1,
	U8 *pbBN_alpha2,
	U8 *pbBN_beta2
	)
{
	S32 iPaiWordLen = 32;
	S32 bytelen;
	U32 bn_A[BNWordLen], bn_B[BNWordLen], bn_T[BNWordLen];

	//Input alpha1 and beta1
	ByteToBN(pbBN_alpha1, pSys_Para->iBNWordLen * 4, bn_A, pSys_Para->iBNWordLen);
	ByteToBN(pbBN_beta1, pSys_Para->iBNWordLen * 4, bn_B, pSys_Para->iBNWordLen);

	//Alpha = alpha1 + alpha2
	ByteToBN(pbBN_alpha2, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_A, bn_A, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);

	//Beta = beta1 + beta2
	ByteToBN(pbBN_beta2, pSys_Para->iBNWordLen * 4, bn_T, pSys_Para->iBNWordLen);
	BN_ModAdd(bn_B, bn_B, bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);

	//s = Alpha^-1 * Beta
	BN_GetInv_Mont(bn_T, bn_A, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->EC_RR_N, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(bn_T, bn_T, bn_B, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);
	BN_GetLastRes(bn_T, pSys_Para->EC_N, pSys_Para->iBNWordLen);
	BNToByte(bn_T, pSys_Para->iBNWordLen, pbBN_s, &bytelen);

	return 1;
}

S32 ECDSA_DiCo_Verify(SECP256K1_Sys_Para * pSys_Para, U8 *pbHash, U8 *pbPubKey, U8 *pbSign)
{
	return ECDSA_Verify(pSys_Para, pbHash, pbPubKey, pbSign);
}