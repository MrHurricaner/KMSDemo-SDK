#include <memory.h>
#include "typedef.h"
#include "common.h"
#include "secp256k1_curve.h"
#include "secp256k1_fp_ecp_test.h"

void SECP256K1_Fp_ECP_KP_Test()
{	
	U32 BN_K[BNWordLen];
	SECP256K1_Fp_ECP_A Point_A;
	SECP256K1_Fp_ECP_A Point_R;
	SECP256K1_Fp_ECP_A Point_Stand;
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para;
	
	S8 *charbuf_x = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	S8 *charbuf_y = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	
	S8 *charbuf_k = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";
	
	S8 *charbuf_x_s = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	S8 *charbuf_y_s = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	
	U8 bytebuf[100];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	
	memset(&m_SECP256K1_Sys_Para, 0, sizeof(m_SECP256K1_Sys_Para));	
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, BNWordLen);

	BN_Reset(BN_K, BNWordLen);
	SECP256K1_Fp_ECP_A_Reset(&Point_A, &m_SECP256K1_Sys_Para);
	SECP256K1_Fp_ECP_A_Reset(&Point_R, &m_SECP256K1_Sys_Para);
	SECP256K1_Fp_ECP_A_Reset(&Point_Stand, &m_SECP256K1_Sys_Para);
	
	//得到K
	charlen = 64;
	result = CharToByte(charbuf_k, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_K, BNWordLen);
	
	//得到点A
	charlen = 64;
	result = CharToByte(charbuf_x, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, Point_A.X, BNWordLen);
	result = CharToByte(charbuf_y, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, Point_A.Y, BNWordLen);
	
	//得到标准结果Q
	charlen = 64;
	result = CharToByte(charbuf_x_s, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, Point_Stand.X, BNWordLen);
	result = CharToByte(charbuf_y_s, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, Point_Stand.Y, BNWordLen);

	//转化Montgomery
	BN_ModMul_Mont(Point_A.X, Point_A.X, m_SECP256K1_Sys_Para.EC_RR_Q, m_SECP256K1_Sys_Para.EC_Q, m_SECP256K1_Sys_Para.EC_nConst_Q, BNWordLen);
	BN_ModMul_Mont(Point_A.Y, Point_A.Y, m_SECP256K1_Sys_Para.EC_RR_Q, m_SECP256K1_Sys_Para.EC_Q, m_SECP256K1_Sys_Para.EC_nConst_Q, BNWordLen);
	
	SECP256K1_Fp_ECP_KP(&Point_R, &Point_A, BN_K, &m_SECP256K1_Sys_Para);

	//转成正常结果
	BN_ModMul_Mont(Point_R.X, Point_R.X, m_SECP256K1_Sys_Para.EC_One, m_SECP256K1_Sys_Para.EC_Q, m_SECP256K1_Sys_Para.EC_nConst_Q, BNWordLen);
	BN_ModMul_Mont(Point_R.Y, Point_R.Y, m_SECP256K1_Sys_Para.EC_One, m_SECP256K1_Sys_Para.EC_Q, m_SECP256K1_Sys_Para.EC_nConst_Q, BNWordLen);

	//得到最终结果
	BN_GetLastRes(Point_R.X, m_SECP256K1_Sys_Para.EC_Q, BNWordLen);
	BN_GetLastRes(Point_R.Y, m_SECP256K1_Sys_Para.EC_Q, BNWordLen);
	
	if (SECP256K1_Fp_ECP_A_JE(&Point_R, &Point_Stand, &m_SECP256K1_Sys_Para))
	{
		printf("The testing of ECP_KP_Test is right!\n");
	}
	else
	{
		printf("The testing of ECP_KP_Test is wrong!\n");
	}

	SECP256K1_Fp_ECP_A_Print(&Point_R, &m_SECP256K1_Sys_Para);
}