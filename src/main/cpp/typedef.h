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

	typedef char				S8;//字符
	typedef short				S16;//
	typedef int				    S32;
	typedef long long 			S64;	

	typedef struct _SECP256K1_FP_ECP_A
	{
		U32 X[BNWordLen];				// X坐标
		U32 Y[BNWordLen];				// Y坐标
	}SECP256K1_Fp_ECP_A;				// struct of affine coordinate

	typedef	struct _SECP256K1_FP_ECP_J
	{
		U32 X[BNWordLen];				// X坐标
		U32 Y[BNWordLen];				// Y坐标
		U32 Z[BNWordLen];				// Z坐标
	}SECP256K1_Fp_ECP_J;				// struct of projective coordinate

	typedef struct _SECP256K1_SYS_PARA
	{
		S32 iBNWordLen;								// 椭圆曲线系统位长对应的字节数
		U32 EC_Q[BNWordLen];						// 椭圆曲线域特征q
		U32 EC_nConst_Q;							// 素数q的常数
		U32 EC_R_Q[BNWordLen];						// R mod q
		U32 EC_RR_Q[BNWordLen];						// RR mod q
		U32 EC_N[BNWordLen];						// 椭圆曲线的阶n	
		U32 EC_nConst_N;							// 素数n的常数
		U32 EC_R_N[BNWordLen];						// R mod n
		U32 EC_RR_N[BNWordLen];						// RR mod n
		U32 EC_Fp_A_Mont[BNWordLen];				// y^2 = x^3 + a*x + b mod q，Montgomery形式
		U32 EC_Fp_B_Mont[BNWordLen];				// y^2 = x^3 + a*x + b mod q，Montgomery形式
		SECP256K1_Fp_ECP_A EC_Fp_G_Mont;			// G1中的基点，Montgomery形式
		U32 EC_One[BNWordLen];

	}SECP256K1_Sys_Para;
	

#ifdef __cplusplus //|| defined(c_plusplus)
}
#endif

#endif


