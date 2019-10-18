#ifndef __HEADER_BN_TEST_H__
#define __HEADER_BN_TEST_H__

#include "bn.h"
#include "common.h"
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif

	void BN_Print_Test();
	void BN_GetBitlen_Test();
	void BN_GetLen_Test();

	void BN_ModAdd_Test();
	void BN_ModSub_Test();

	void  BN_ModAdd_Test_cd();
	void  BN_ModSub_Test_cd();
	void  BN_Modkkk_Test_cd();


	void BN_ModMul_Mont_Test();
	void BN_ModSqu_Mont_Test();
	void BN_GetInv_Mont_Test();
	void BN_ModExp_Test();
	//void BN_GetInv_Test();
	//===================
	void BN_GetR_Test();
	void BN_Mul_Test();
	void BN_Div_Test();
	void BN_PrimeTest_Test();
	void BN_GenPrime_Test();


#ifdef  __cplusplus
}
#endif

#endif

