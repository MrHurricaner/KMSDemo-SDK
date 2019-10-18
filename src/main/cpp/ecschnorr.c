#include "ecschnorr.h"

#include "secp256k1_curve.h"
#include "secp256k1_fp_ecp.h"
#include "bn.h"
#include "common.h"
#include "sha2.h"

S32 ECSchnorr_KeyGen(U8 *pbPubKey, SECP256K1_Sys_Para *pSys_Para, U8 *pbPriKey)
{
	SECP256K1_Fp_ECP_A Ap;
	U32	x[BNWordLen];
	S32 bytelen;

	//Input transform
	ByteToBN(pbPriKey, BNByteLen, x, BNWordLen);

	//A1 = [x1]G
	SECP256K1_Fp_ECP_KP(&Ap, &pSys_Para->EC_Fp_G_Mont, x, pSys_Para);//A1 = [x1]G
	BN_ModMul_Mont(Ap.X, Ap.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Ap.Y, Ap.Y, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Ap.X, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Ap.Y, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BNToByte(Ap.X, BNWordLen, pbPubKey, &bytelen);
	BNToByte(Ap.Y, BNWordLen, pbPubKey + BNByteLen, &bytelen);

	return 1;
}

S32 ECSchnorr_Sign(U8 *pbSign, SECP256K1_Sys_Para *pSys_Para, U8 *pbHash, U8 *pbPriKey, U8 *pbRand)
{
	SECP256K1_Fp_ECP_A Rp;
	U32 k[BNWordLen], e[BNWordLen], s[BNWordLen];
	U8 r[2 * BNByteLen];
	sha256_context ctx;
	S32 bytelen;

	//Init and input
	ByteToBN(pbRand, BNByteLen, k, BNWordLen);
	ByteToBN(pbPriKey, BNByteLen, s, BNWordLen);

	//r = [k]G; 
	SECP256K1_Fp_ECP_KP(&Rp, &pSys_Para->EC_Fp_G_Mont, k, pSys_Para);
	BN_ModMul_Mont(Rp.X, Rp.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Rp.Y, Rp.Y, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Rp.X, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Rp.Y, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BNToByte(Rp.X, BNWordLen, r, &bytelen);
	BNToByte(Rp.Y, BNWordLen, r + BNByteLen, &bytelen);

	//e = H(r||M)
	sha256_starts(&ctx);
	sha256_update(&ctx, r, 2 * BNByteLen);
	sha256_update(&ctx, pbHash, BNByteLen);
	sha256_finish(&ctx, r);
	ByteToBN(r, BNByteLen, e, BNWordLen);

	//s = k - x * e
	BN_ModMul_Mont(s, s, e, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(s, s, pSys_Para->EC_RR_N, pSys_Para->EC_N, pSys_Para->EC_nConst_N, pSys_Para->iBNWordLen);
	BN_ModSub(s, k, s, pSys_Para->EC_N, pSys_Para->iBNWordLen);

	//Output
	BNToByte(e, BNWordLen, pbSign, &bytelen);
	BNToByte(s, BNWordLen, pbSign + BNByteLen, &bytelen);

	return 1;
}

S32 ECSchnorr_Verify(SECP256K1_Sys_Para * pSys_Para, U8 *pbHash, U8 *pbPubKey, U8 *pbSign)
{
	SECP256K1_Fp_ECP_A Rp, Yp;
	SECP256K1_Fp_ECP_J Jp;
	U32 e[BNWordLen], s[BNWordLen];
	U8 r[2 * BNByteLen];
	sha256_context ctx;
	S32 i, bytelen;

	//Init and input
	ByteToBN(pbSign, BNByteLen, e, BNWordLen);
	ByteToBN(pbSign + BNByteLen, BNByteLen, s, BNWordLen);
	ByteToBN(pbPubKey, BNByteLen, Yp.X, BNWordLen);
	ByteToBN(pbPubKey + BNByteLen, BNByteLen, Yp.Y, BNWordLen);
	BN_ModMul_Mont(Yp.X, Yp.X, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Yp.Y, Yp.Y, pSys_Para->EC_RR_Q, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);

	//r = [s]G + [e]Y
	SECP256K1_Fp_ECP_KP(&Rp, &pSys_Para->EC_Fp_G_Mont, s, pSys_Para);
	SECP256K1_Fp_ECP_KP(&Yp, &Yp, e, pSys_Para);
	SECP256K1_Fp_ECP_AToJ(&Jp, &Rp, pSys_Para);
	SECP256K1_Fp_ECP_JAddAToJ(&Jp, &Jp, &Yp, pSys_Para);
	SECP256K1_Fp_ECP_JToA(&Rp, &Jp, pSys_Para);
	BN_ModMul_Mont(Rp.X, Rp.X, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_ModMul_Mont(Rp.Y, Rp.Y, pSys_Para->EC_One, pSys_Para->EC_Q, pSys_Para->EC_nConst_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Rp.X, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BN_GetLastRes(Rp.Y, pSys_Para->EC_Q, pSys_Para->iBNWordLen);
	BNToByte(Rp.X, BNWordLen, r, &bytelen);
	BNToByte(Rp.Y, BNWordLen, r + BNByteLen, &bytelen);

	//e = H(r||M)
	sha256_starts(&ctx);
	sha256_update(&ctx, r, 2 * BNByteLen);
	sha256_update(&ctx, pbHash, BNByteLen);
	sha256_finish(&ctx, r);

	//Check e
	for (i = 0; i < BNByteLen; i++)
	{
		if (r[i] != pbSign[i])
			return 0;
	}

	return 1;
}