#ifndef __HEADER_PAILLER_TEST_H__
#define __HEADER_PAILLER_TEST_H__

#include "pailler.h"

#ifdef  __cplusplus
extern "C" {
#endif


	void PAI_KeyGen_Test();
	void PAI_Encryption_Test();
	void PAI_Decryption_Test();
	void PAI_HomAdd_Test();
	/****/
	void PAI_MessageAdd(U8 *Message, U8 *Message1, U8 *Message2,  S32 Message_Len, U8 *Module, S32 Module_Len);
	void PAI_MessageAdd_Test();
	void PAI_Test();
#ifdef  __cplusplus
}
#endif

#endif
