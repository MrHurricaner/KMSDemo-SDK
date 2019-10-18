#ifndef __HEADER_U8OPERATION_H__
#define __HEADER_U8OPERATION_H__



#include "common.h"
#include <stdlib.h>



#ifdef  __cplusplus
extern "C" {
#endif
		  void U8_Print(U8* pwSource,S32 len);
	      void U8ArrayCopy(U8* pwDest,S32 Dest_begin,U8* pwSource,S32 Sour_begin,S32 copylen);
		  void U8OXR(U8* pwResult,U8* pwSourceA,U8* pwSourceB,S32 len);
		  void Shuffle(S32* new_flag,S32* flag,S32 len);
		  S32  U8_JE(U8* pwX,U8* pwY,S32 len);
		  //S32 ByteTo_FpPoint(SM9_Fp_ECP_A *pFp_Point, U8 *pbFp_Point, S32 nFp_Point_len);

#ifdef  __cplusplus
}
#endif


#endif