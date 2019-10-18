#include "u8operation.h"
///*
//*��������byte����ת��ΪPoint
//*���룺���飬���ݵĳ���
//*�����SM9_Fp_ECP_A���͵ĵ�
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
*��������������������˳��
*���룺������˳�������flag�����ݳ���len
*��������������
*/
void Shuffle(S32* new_flag,S32* flag,S32 len)
{
/*******************************************/
	S32 i;//ѭ������
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
*��������ӡU8����
*���룺����ӡ����pwSource,���鳤��
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
*����������U8����
*���룺Դ����pSource,Ŀ������
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
*����������U8�������
*���룺�������������飬sourceA,sourceB,����
*�����������result
*/
void  U8OXR(U8* pwResult,U8* pwSourceA,U8* pwSourceB,S32 len)
{
	/*******************************************/
	S32 i;//ѭ������

	i = 0;
/*******************************************/
	for(i = 0;i<len;i++)
	{
		pwResult[i] = pwSourceA[i]^pwSourceB[i];
	}
	
}
/*
*�������ж�����U8�����Ƿ���ȣ�
*���룺���жϵ�����U8���飬pwX,pwY������len
*�������ȣ�����1������ȷ���0��
*/
S32  U8_JE(U8* pwX,U8* pwY,S32 len)
{
/*******************************************/
	S32 i;//ѭ������

	i = 0;
/*******************************************/
	for(i = 0;i<len;i++)
	{
		if(pwX[i]!=pwY[i])
			return 0;
	}
	return 1;
}