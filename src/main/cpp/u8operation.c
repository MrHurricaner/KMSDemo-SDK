#include "u8operation.h"
///*
//*描述：将byte数据转化为Point
//*输入：数组，数据的长度
//*输出：SM9_Fp_ECP_A类型的点
//*/
//S32 ByteTo_FpPoint(SM9_Fp_ECP_A *pFp_Point, U8 *pbFp_Point, S32 nFp_Point_len)
//{
//	U8 uPoint_X[4*BNWordLen] = {0};
//	U8 uPoint_Y[4*BNWordLen] = {0};
//	U32 BN_Point_X[BNWordLen];
//	U32 BN_Point_Y[BNWordLen];
//	S32 result = 0;
//	BN_Reset(BN_Point_X, BNWordLen);
//	BN_Reset(BN_Point_Y, BNWordLen);
//
///*******************************************/
//	if(nFp_Point_len != 8*BNWordLen)
//	{
//		return -1;
//	}
//	U8ArrayCopy(uPoint_X, 0, pbFp_Point, 0, 4*BNWordLen);
//	U8ArrayCopy(uPoint_Y, 0, pbFp_Point, 4*BNWordLen, 4*BNWordLen);
//	result = ByteToBN(uPoint_X, 4*BNWordLen, pFp_Point->X, BNWordLen);
//	result = ByteToBN(uPoint_Y, 4*BNWordLen, pFp_Point->Y, BNWordLen);
//	return result;
//}

/*
*描述：扰乱数据内数据顺序
*输入：待打乱顺序的数组flag，数据长度len
*输出：乱序后数组
*/
void Shuffle(S32* new_flag,S32* flag,S32 len)
{
/*******************************************/
	S32 i;//循环变量
	S32 tag;
	S32 stop;
	stop = -1;
	i = 0;
/*******************************************/
	for(i = 0;i<len;i++)
	{
		tag = rand()%len;
		if(flag[tag] == stop)
		{
			while(flag[tag]==stop)
			{
				tag = (tag +1)%len;
			}
		}
		new_flag[i] = flag[tag];
		flag[tag] = stop;
	}
}
/*
*描述：打印U8数组
*输入：待打印数组pwSource,数组长度
*/
void U8_Print(U8* pwSource,S32 len)
{
/************************************/
	S32 i;
/************************************/
	for(i = 0;i<len;i++)
	{
		printf("%02X",pwSource[i]);
	}
	printf("\n");
}
/*
*描述：复制U8数组
*输入：源数据pSource,目标数组
*/
void U8ArrayCopy(U8* pwDest,S32 Dest_begin,U8* pwSource,S32 Sour_begin,S32 copylen)
{
/************************************/
	S32 i;
/************************************/
	for(i = 0;i<copylen;i++)
	{
		pwDest[i+Dest_begin] = pwSource[i+Sour_begin];
	}
}


/*
*描述：两个U8数组异或
*输入：带异或的两个数组，sourceA,sourceB,长度
*输出：异或后结果result
*/
void  U8OXR(U8* pwResult,U8* pwSourceA,U8* pwSourceB,S32 len)
{
	/*******************************************/
	S32 i;//循环变量

	i = 0;
/*******************************************/
	for(i = 0;i<len;i++)
	{
		pwResult[i] = pwSourceA[i]^pwSourceB[i];
	}
	
}
/*
*描述：判断两个U8数组是否相等，
*输入：待判断的两个U8数组，pwX,pwY，长度len
*输出：相等，返回1，不相等返回0；
*/
S32  U8_JE(U8* pwX,U8* pwY,S32 len)
{
/*******************************************/
	S32 i;//循环变量

	i = 0;
/*******************************************/
	for(i = 0;i<len;i++)
	{
		if(pwX[i]!=pwY[i])
			return 0;
	}
	return 1;
}