#ifndef __HEADER_SECP256K1_Fp_ECP_H__
#define __HEADER_SECP256K1_Fp_ECP_H__

#include "bn.h"

#ifdef  __cplusplus
extern "C" {
#endif

	void SECP256K1_Fp_ECP_A_Print(SECP256K1_Fp_ECP_A *pECP_A, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_J_Print(SECP256K1_Fp_ECP_J *pECP_A, SECP256K1_Sys_Para *pSysPara);

	void SECP256K1_Fp_ECP_A_Reset(SECP256K1_Fp_ECP_A *pECP_A, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_J_Reset(SECP256K1_Fp_ECP_J *pECP_J, SECP256K1_Sys_Para *pSysPara);

	S32 SECP256K1_Fp_ECP_A_JE(SECP256K1_Fp_ECP_A *pPointA, SECP256K1_Fp_ECP_A *pPointB, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_A_Assign(SECP256K1_Fp_ECP_A *pPointA, SECP256K1_Fp_ECP_A *pPointB, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_J_Assign(SECP256K1_Fp_ECP_J *pPointA, SECP256K1_Fp_ECP_J *pPointB, SECP256K1_Sys_Para *pSysPara);

	void SECP256K1_Fp_ECP_AToJ(SECP256K1_Fp_ECP_J *pJ_Point, SECP256K1_Fp_ECP_A *pA_Point, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_JToA(SECP256K1_Fp_ECP_A *pAp, SECP256K1_Fp_ECP_J *pJp, SECP256K1_Sys_Para *pSysPara);

	void SECP256K1_Fp_ECP_JAddAToJ(SECP256K1_Fp_ECP_J *pJ_Sum, SECP256K1_Fp_ECP_J *pJp, SECP256K1_Fp_ECP_A *pAp, SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_DoubleJToJ(SECP256K1_Fp_ECP_J *pJp_Result, SECP256K1_Fp_ECP_J *pJp,  SECP256K1_Sys_Para *pSysPara);
	void SECP256K1_Fp_ECP_KP(SECP256K1_Fp_ECP_A *pKP, SECP256K1_Fp_ECP_A *pAp, U32 *pwK, SECP256K1_Sys_Para *pSysPara);

	void SECP256K1_Fp_ECP_ByteToA(SECP256K1_Fp_ECP_A *pAp, SECP256K1_Sys_Para *pSysPara, U8 *pbBytebuf);
	void SECP256K1_Fp_ECP_AToByte(U8 *pbBytebuf, SECP256K1_Sys_Para *pSysPara, SECP256K1_Fp_ECP_A *pAp);

#ifdef  __cplusplus
}
#endif


#endif

