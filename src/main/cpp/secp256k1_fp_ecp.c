/* 
*Copyright (c) 2016, ���������Ƽ����޹�˾* 
*All rights reserved.* 
*
*�ļ����ƣ�SECP256K1_fp_ecp.c
*�ļ���ʶ��
*ժ    Ҫ��ʵ��F(p)����Բ����x^3=y^2+a*x+b
*
*��ǰ�汾��1.0
*��    �ߣ��ε±�
*��	   �ڣ�2016��10��01��
*
*/
#include "secp256k1_fp_ecp.h"
#include "common.h"
/*
=======================================================================================================================
	����: ��ӡ��Բ���ߵ�(���������)
	����:
		 pECP_A:					����ӡ����Բ���ߵ�(���������)
		 iBNWordLen:			����������
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_A_Print(SECP256K1_Fp_ECP_A *pECP_A, SECP256K1_Sys_Para *pSysPara)
{
	S32 iBNWordLen = pSysPara->iBNWordLen;

	BN_Print(pECP_A->X, iBNWordLen);
	BN_Print(pECP_A->Y, iBNWordLen);
}

/*
=======================================================================================================================
	����: ��ӡ��Բ���ߵ�(���������)
	����:
		 pECP_A:					����ӡ����Բ���ߵ�(���������)
		 iBNWordLen:			����������
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_J_Print(SECP256K1_Fp_ECP_J *pECP_A, SECP256K1_Sys_Para *pSysPara)
{
	S32 iBNWordLen = pSysPara->iBNWordLen;

	BN_Print(pECP_A->X, iBNWordLen);
	BN_Print(pECP_A->Y, iBNWordLen);
	BN_Print(pECP_A->Z, iBNWordLen);
}

/*
=======================================================================================================================
	����: ��Բ���ߵ�(���������)����
	����:
		 pECP_A:					���������Բ���ߵ�(���������)
		 iBNWordLen:			����������
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_A_Reset(SECP256K1_Fp_ECP_A *pECP_A, SECP256K1_Sys_Para *pSysPara)
{
	S32 iBNWordLen = pSysPara->iBNWordLen;

	BN_Reset(pECP_A->X, iBNWordLen);
	BN_Reset(pECP_A->Y, iBNWordLen);
}

/*
=======================================================================================================================
	����: ��Բ���ߵ�(�ſɱ���Ӱ�����)����
	����:
		 pECP_J:					���������Բ���ߵ�(�ſɱ���Ӱ�����)
		 iBNWordLen:			����������
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_J_Reset(SECP256K1_Fp_ECP_J *pECP_J, SECP256K1_Sys_Para *pSysPara)
{
	S32 iBNWordLen = pSysPara->iBNWordLen;

	BN_Reset(pECP_J->X, iBNWordLen);
	BN_Reset(pECP_J->Y, iBNWordLen);
	BN_Reset(pECP_J->Z, iBNWordLen);
}

/*
=======================================================================================================================
	����:�ж�����������Ƿ����
	����:	
			pPointA: ��Բ�����ϵĵ�A
			pPointB: ��Բ�����ϵĵ�B
			pEc:		��Բ���߲����ṹ
=======================================================================================================================
*/
S32 SECP256K1_Fp_ECP_A_JE(SECP256K1_Fp_ECP_A *pPointA, SECP256K1_Fp_ECP_A *pPointB, SECP256K1_Sys_Para *pSysPara)
{
	if (BN_JE(pPointA->X, pPointB->X, pSysPara->iBNWordLen) != 1)
	{
		return 0;
	}

	if ( BN_JE(pPointA->Y, pPointB->Y, pSysPara->iBNWordLen) != 1)
	{
		return 0;
	}
	
	return 1;
}

/*
=======================================================================================================================
	����:����㸳ֵ��pPointA <= pPointB
	����:
			pPointA: ��Բ�����ϵĵ�A
			pPointB: ��Բ�����ϵĵ�B
			pEc:		��Բ���߲����ṹ
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_A_Assign(SECP256K1_Fp_ECP_A *pPointA, SECP256K1_Fp_ECP_A *pPointB, SECP256K1_Sys_Para *pSysPara)
{
	BN_Assign(pPointA->X, pPointB->X, pSysPara->iBNWordLen);
	BN_Assign(pPointA->Y, pPointB->Y, pSysPara->iBNWordLen);
}


/*
=======================================================================================================================
	����:��Ӱ����㸳ֵ��pPointA <= pPointB
	����:
			pPointA: ��Բ�����ϵĵ�A
			pPointB: ��Բ�����ϵĵ�B
			pEc:		��Բ���߲����ṹ
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_J_Assign(SECP256K1_Fp_ECP_J *pPointA, SECP256K1_Fp_ECP_J *pPointB, SECP256K1_Sys_Para *pSysPara)
{
	BN_Assign(pPointA->X, pPointB->X, pSysPara->iBNWordLen);
	BN_Assign(pPointA->Y, pPointB->Y, pSysPara->iBNWordLen);
	BN_Assign(pPointA->Z, pPointB->Z, pSysPara->iBNWordLen);
}

/*
=======================================================================================================================
	����:�����ת��Ϊ��Ӱ�����
	����:
		pA_Point:��������㣨Montgomery��ʽ�ģ�
	���:
		pJ_Point:��Ӱ����㣨Montgomery��ʽ�ģ�
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_AToJ(SECP256K1_Fp_ECP_J *pJ_Point, SECP256K1_Fp_ECP_A *pA_Point, SECP256K1_Sys_Para *pSysPara)
{
	BN_Assign(pJ_Point->X, pA_Point->X, pSysPara->iBNWordLen);
	BN_Assign(pJ_Point->Y, pA_Point->Y, pSysPara->iBNWordLen);

	//BN_Reset(pJ_Point->Z, pSysPara->iBNWordLen);
	//pJ_Point->Z[0] = 0x00000001;
	BN_Assign(pJ_Point->Z, pSysPara->EC_R_Q, pSysPara->iBNWordLen);
}

/*
=======================================================================================================================
����:��Ӱ��ת��Ϊ���������
����:pA_Point:���������
pJ_Point:��Ӱ�����
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_JToA(SECP256K1_Fp_ECP_A *pAp, SECP256K1_Fp_ECP_J *pJp, SECP256K1_Sys_Para *pSysPara)
{
	/***************************/
	U32 bn_tmp[BNWordLen];
	/***************************/
	
	if (BN_IsZero(pJp->Z, pSysPara->iBNWordLen))
	{
		SECP256K1_Fp_ECP_A_Reset(pAp, pSysPara);
		return;
	}
	
	BN_Reset(bn_tmp, pSysPara->iBNWordLen);
	//BN_ModMul_Stand(bn_tmp, pJp->Z, pJp->Z, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp = Z ^ 2
	BN_ModSqu_Mont(bn_tmp, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp = Z ^ 2
	//BN_ModMul_Stand(bn_tmp, bn_tmp, pJp->Z, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp = Z ^ 3
	BN_ModMul_Mont(bn_tmp, bn_tmp, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp = Z ^ 3

	//BN_GetInv(bn_tmp, bn_tmp, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp = Z ^ -3
	BN_ModMul_Mont(bn_tmp, bn_tmp, pSysPara->EC_One, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);
	BN_GetInv_Mont(bn_tmp, bn_tmp,  pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->EC_RR_Q, pSysPara->iBNWordLen);

	//BN_ModMul_Stand(pAp->Y, pJp->Y, bn_tmp, pSysPara->EC_Q, pSysPara->iBNWordLen);//Y1 = Y * Z^-3
	BN_ModMul_Mont(pAp->Y, pJp->Y, bn_tmp, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//Y1 = Y * Z^-3

	//BN_ModMul_Stand(bn_tmp, bn_tmp, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp = Z^-2
	BN_ModMul_Mont(bn_tmp, bn_tmp, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp = Z^-2
	//BN_ModMul_Stand(pAp->X, pJp->X, bn_tmp, pSysPara->EC_Q, pSysPara->iBNWordLen);//X1 = X * Z ^ -2
	BN_ModMul_Mont(pAp->X, pJp->X, bn_tmp, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//X1 = X * Z ^ -2
}


/*
=======================================================================================================================
	����:��Բ���ߵĵ������,J_Sum = Jp + Ap
	����:
			pJp:��Բ��������Jacobian�����ʾ�ĵ�A
			pAp:��Բ��������Affine�����ʾ�ĵ�B
			pEc:��Բ���߲������ݽṹ
	���:
			pJ_Sum:��ӽ��,��Jacobian�����ʾ�ĵ�
	����ֵ:
			��
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_JAddAToJ(SECP256K1_Fp_ECP_J *pJ_Sum, SECP256K1_Fp_ECP_J *pJp, SECP256K1_Fp_ECP_A *pAp, SECP256K1_Sys_Para *pSysPara)
{
	/************************/
	U32 bn_tmp1[BNWordLen];
	U32 bn_tmp2[BNWordLen];
	U32 bn_tmp3[BNWordLen];
	/************************/
	
	BN_Reset(bn_tmp1, BNWordLen);
	BN_Reset(bn_tmp2, BNWordLen);
	BN_Reset(bn_tmp3, BNWordLen);
	
	//BN_ModMul_Stand(bn_tmp3, pJp->Z, pJp->Z, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp3 = Z1^2
	BN_ModMul_Mont(bn_tmp3, pJp->Z, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp3 = Z1^2

	//BN_ModMul_Stand(bn_tmp2, bn_tmp3, pJp->Z, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp2 = Z1^3
	BN_ModMul_Mont(bn_tmp2, bn_tmp3, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp2 = Z1^3
	BN_ModMul_Mont(bn_tmp3, bn_tmp3, pAp->X, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp3 = X2 * Z1^2 = A
	BN_ModSub(bn_tmp3, bn_tmp3, pJp->X,pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp3 = A - X1 = C
	BN_ModMul_Mont(pJ_Sum->Z, pJp->Z, bn_tmp3, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//Z3 = Z1 * C
	BN_ModMul_Mont(bn_tmp2, bn_tmp2, pAp->Y, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp2 = Y2 * Z1 ^ 3 = B
	BN_ModSub(bn_tmp2, bn_tmp2, pJp->Y, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp2 = B - Y1 = D
	BN_ModMul_Mont(bn_tmp1, bn_tmp3, bn_tmp3,pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp1 = C ^ 2
	BN_ModMul_Mont(bn_tmp3, bn_tmp3, bn_tmp1, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp3 = C ^ 3
	BN_ModMul_Mont(bn_tmp1, bn_tmp1, pJp->X, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp1 = X1 * C^2
	BN_ModAdd(pJ_Sum->X, bn_tmp1, bn_tmp1, pSysPara->EC_Q, pSysPara->iBNWordLen);//X3 = 2 X1 * C^2
	BN_ModAdd(pJ_Sum->X, pJ_Sum->X, bn_tmp3, pSysPara->EC_Q, pSysPara->iBNWordLen);//X3 = C ^ 3 + 2 X1 * C^2
	BN_ModMul_Mont(pJ_Sum->Y, pJp->Y, bn_tmp3, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//Y3 = Y1 * C^3
	BN_ModMul_Mont(bn_tmp3, bn_tmp2, bn_tmp2, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp3 = D^2
	BN_ModSub(pJ_Sum->X, bn_tmp3, pJ_Sum->X, pSysPara->EC_Q, pSysPara->iBNWordLen);//X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
	BN_ModSub(bn_tmp1, bn_tmp1, pJ_Sum->X, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp1 = X1 * C ^ 2 - X3
	BN_ModMul_Mont(bn_tmp1, bn_tmp1, bn_tmp2, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp1 = D * (X1 * C ^ 2 - X3)
	BN_ModSub(pJ_Sum->Y, bn_tmp1, pJ_Sum->Y, pSysPara->EC_Q, pSysPara->iBNWordLen);//Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
}

/*
=======================================================================================================================
	����:��Բ���ߵĵ㱶����,Jp_Result = 2Jp
	����:
				pJp:��Բ��������Jacobian�����ʾ�ĵ�
				pEc:��Բ���߲������ݽṹ
	���:
				pJp_Result:�㱶���,��Jacobian�����ʾ�ĵ�
	����ֵ:
				��
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_DoubleJToJ(SECP256K1_Fp_ECP_J *pJp_Result, SECP256K1_Fp_ECP_J *pJp,  SECP256K1_Sys_Para *pSysPara)
{
	/************************/
	U32 bn_tmp1[BNWordLen];
	U32 bn_tmp2[BNWordLen];
	U32 bn_tmp3[BNWordLen];
	U32 bn_tmp4[BNWordLen];
	U32 bn_tmp5[BNWordLen];
	//S32 iBNWordLen = 0;
	/************************/
	
	BN_Reset(bn_tmp1, BNWordLen);
	BN_Reset(bn_tmp2, BNWordLen);
	BN_Reset(bn_tmp3, BNWordLen);
	BN_Reset(bn_tmp4, BNWordLen);
	BN_Reset(bn_tmp5, BNWordLen);
	
	//iBNWordLen = iBNWord;
	BN_ModMul_Mont(bn_tmp4, pJp->Y, pJp->Y, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp4 = Y1 ^ 2
	BN_ModMul_Mont(bn_tmp1, bn_tmp4, pJp->X, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp1 = X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp1, bn_tmp1, bn_tmp1, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp1 = 2 X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp1, bn_tmp1, bn_tmp1, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp1 = 4 X1 * Y1 ^ 2 = A
	BN_ModMul_Mont(bn_tmp2, bn_tmp4, bn_tmp4, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp2 = Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp2 = 2 Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp2 = 4 Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp2 = 8 Y1 ^ 4 = B
	
	BN_ModMul_Mont(bn_tmp4, pJp->Z, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp4 = Z1 ^ 2
	BN_ModMul_Mont(bn_tmp4, bn_tmp4, bn_tmp4, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp4 = Z1 ^ 4
	BN_ModMul_Mont(bn_tmp4, bn_tmp4, pSysPara->EC_Fp_A_Mont, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp4 = a Z1 ^ 4
	
	BN_ModMul_Mont(bn_tmp3, pJp->X, pJp->X, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp3 = X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp3, bn_tmp3, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp5 = 2 X1 ^ 2
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp5, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp3 = 3 X1 ^ 2
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp4, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp3 = 3 X1 ^ 2 + aZ1 ^ 4 = C
	BN_ModMul_Mont(pJp_Result->X, bn_tmp3, bn_tmp3, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//X3 = C ^ 2
	BN_ModSub(pJp_Result->X, pJp_Result->X, bn_tmp1, pSysPara->EC_Q, pSysPara->iBNWordLen);//X3 = C ^ 2 - A
	BN_ModSub(pJp_Result->X, pJp_Result->X, bn_tmp1, pSysPara->EC_Q, pSysPara->iBNWordLen);//X3 = C ^ 2 - 2A
	BN_ModSub(bn_tmp1, bn_tmp1, pJp_Result->X, pSysPara->EC_Q, pSysPara->iBNWordLen);//tmp1 = A - X3
	BN_ModMul_Mont(bn_tmp1, bn_tmp1, bn_tmp3, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//tmp1 = C * (A - X3)
	BN_ModMul_Mont(pJp_Result->Z, pJp->Y, pJp->Z, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);//Z3 = Y1 * Z1
	BN_ModAdd(pJp_Result->Z, pJp_Result->Z, pJp_Result->Z, pSysPara->EC_Q, pSysPara->iBNWordLen);//Z3 = 2 Y1 * Z1
	BN_ModSub(pJp_Result->Y, bn_tmp1, bn_tmp2, pSysPara->EC_Q, pSysPara->iBNWordLen);//Y3 = C * (A - X3) - B
}

/*
=======================================================================================================================
	����:������Բ�����ϵĵ��KP = K * Ap
	����:
		pAp:��Բ��������Affine�����ʾ�ĵ�
		np:Ԥ������
		pEc:��Բ���߲������ݽṹ
		K:������
	���:
		KP:�����������Բ������Affine�����ʾ�ĵ�
	����ֵ:
		��
=======================================================================================================================
*/
void SECP256K1_Fp_ECP_KP(SECP256K1_Fp_ECP_A *pKP, SECP256K1_Fp_ECP_A *pAp, U32 *pwK, SECP256K1_Sys_Para *pSysPara)
{
	/***********************************/
	S32 bitlen = 0;
	S32 i = 0;
	SECP256K1_Fp_ECP_J Jp_tmp;
	U32 flag[32] = {0x00000001,0x00000002,0x00000004,0x00000008,
		0x00000010,0x00000020,0x00000040,0x00000080,
		0x00000100,0x00000200,0x00000400,0x00000800,
		0x00001000,0x00002000,0x00004000,0x00008000,
		0x00010000,0x00020000,0x00040000,0x00080000,
		0x00100000,0x00200000,0x00400000,0x00800000,
		0x01000000,0x02000000,0x04000000,0x08000000,
		0x10000000,0x20000000,0x40000000,0x80000000};
	/***********************************/
	
	bitlen = BN_GetBitLen(pwK, pSysPara->iBNWordLen);
	if (bitlen == 0)
	{
		SECP256K1_Fp_ECP_A_Reset(pKP, pSysPara);
		return;
	}
	else
	{		
		SECP256K1_Fp_ECP_J_Reset(&Jp_tmp, pSysPara);
		SECP256K1_Fp_ECP_AToJ(&Jp_tmp, pAp, pSysPara);
		for (i = bitlen - 2; i >= 0; i--)
		{
			SECP256K1_Fp_ECP_DoubleJToJ(&Jp_tmp, &Jp_tmp, pSysPara);
			if (pwK[i / WordLen] & flag[i % WordLen])
				SECP256K1_Fp_ECP_JAddAToJ(&Jp_tmp, &Jp_tmp, pAp, pSysPara);
		}
		SECP256K1_Fp_ECP_JToA(pKP, &Jp_tmp, pSysPara);
		return;
	}
}

void SECP256K1_Fp_ECP_ByteToA(SECP256K1_Fp_ECP_A *pAp, SECP256K1_Sys_Para *pSysPara, U8 *pbBytebuf)
{
	ByteToBN(pbBytebuf, BNByteLen, pAp->X, BNWordLen);
	ByteToBN(pbBytebuf + BNByteLen, BNByteLen, pAp->Y, BNWordLen);
	BN_ModMul_Mont(pAp->X, pAp->X, pSysPara->EC_RR_Q, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);
	BN_ModMul_Mont(pAp->Y, pAp->Y, pSysPara->EC_RR_Q, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);
}

void SECP256K1_Fp_ECP_AToByte(U8 *pbBytebuf, SECP256K1_Sys_Para *pSysPara, SECP256K1_Fp_ECP_A *pAp)
{
	U32 bn_X[BNWordLen], bn_Y[BNWordLen];
	S32 bytelen;

	BN_Reset(bn_X, BNWordLen);
	BN_Reset(bn_Y, BNWordLen);

	BN_ModMul_Mont(bn_X, pAp->X, pSysPara->EC_One, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);
	BN_ModMul_Mont(bn_Y, pAp->Y, pSysPara->EC_One, pSysPara->EC_Q, pSysPara->EC_nConst_Q, pSysPara->iBNWordLen);
	BN_GetLastRes(bn_X, pSysPara->EC_Q, pSysPara->iBNWordLen);
	BN_GetLastRes(bn_Y, pSysPara->EC_Q, pSysPara->iBNWordLen);
	BNToByte(bn_X, BNWordLen, pbBytebuf, &bytelen);
	BNToByte(bn_Y, BNWordLen, pbBytebuf + BNByteLen, &bytelen);
}