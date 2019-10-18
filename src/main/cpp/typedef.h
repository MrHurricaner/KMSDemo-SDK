#ifndef __HEADER_TYPEDEF_H__
#define __HEADER_TYPEDEF_H__

#include "macro.h"

#ifdef __cplusplus //|| defined(c_plusplus)
extern "C"{
#endif

	typedef unsigned char		U8;//BYTE 8bit
	typedef unsigned short		U16;// 16bit
	typedef unsigned int		U32;//
	typedef unsigned long long	U64;

	typedef char				S8;//�ַ�
	typedef short				S16;//
	typedef int				    S32;
	typedef long long 			S64;	

	typedef struct _SECP256K1_FP_ECP_A
	{
		U32 X[BNWordLen];				// X����
		U32 Y[BNWordLen];				// Y����
	}SECP256K1_Fp_ECP_A;				// struct of affine coordinate

	typedef	struct _SECP256K1_FP_ECP_J
	{
		U32 X[BNWordLen];				// X����
		U32 Y[BNWordLen];				// Y����
		U32 Z[BNWordLen];				// Z����
	}SECP256K1_Fp_ECP_J;				// struct of projective coordinate

	typedef struct _SECP256K1_SYS_PARA
	{
		S32 iBNWordLen;								// ��Բ����ϵͳλ����Ӧ���ֽ���
		U32 EC_Q[BNWordLen];						// ��Բ����������q
		U32 EC_nConst_Q;							// ����q�ĳ���
		U32 EC_R_Q[BNWordLen];						// R mod q
		U32 EC_RR_Q[BNWordLen];						// RR mod q
		U32 EC_N[BNWordLen];						// ��Բ���ߵĽ�n	
		U32 EC_nConst_N;							// ����n�ĳ���
		U32 EC_R_N[BNWordLen];						// R mod n
		U32 EC_RR_N[BNWordLen];						// RR mod n
		U32 EC_Fp_A_Mont[BNWordLen];				// y^2 = x^3 + a*x + b mod q��Montgomery��ʽ
		U32 EC_Fp_B_Mont[BNWordLen];				// y^2 = x^3 + a*x + b mod q��Montgomery��ʽ
		SECP256K1_Fp_ECP_A EC_Fp_G_Mont;			// G1�еĻ��㣬Montgomery��ʽ
		U32 EC_One[BNWordLen];

	}SECP256K1_Sys_Para;
	

#ifdef __cplusplus //|| defined(c_plusplus)
}
#endif

#endif


