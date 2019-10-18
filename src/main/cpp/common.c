#include "common.h"

/*
=======================================================================================================================
	描述:把S8类型数组转换成U8类型数组
	输入:
		pCharBuf:S8类型数组，为'0'-'9'或'a'-'f'或'A'-'F',如果不是则返回0
		charlen:S8类型数组长度
	输出:
		pByteBuf:U8类型数组,如果charlen为奇数,pByteBuf长度至少为charlen/2+1,否则至少为charlen/2
		bytelen:U8类型数组长度,
	返回值:
		0:转换过程错误
		1:转换成功
=======================================================================================================================
*/
S32 CharToByte(S8 *pCharBuf, S32 charlen, S8 *pByteBuf, S32 *bytelen)
{
	/*******************/
	S32 i = 0;
	S32 charlen_tmp = 0;
	U8 hdata = 0;
	U8 ldata = 0;
	S8 hstr = 0;
	S8 lstr = 0;
	/*******************/


	charlen_tmp = charlen;
	if (charlen_tmp & LSBOfWord)//如果charlen是奇数
	{
		charlen_tmp += 1;
		*bytelen = charlen_tmp >> 1;
		if (ConvertHexChar(pCharBuf[0], &ldata) == 1)//单独处理第一位
		{
			pByteBuf[0] = ldata;
		}
		for (i = 1; i < *bytelen; i++)
		{
			if (ConvertHexChar(pCharBuf[2 * i - 1], &hdata) == 1)//第一个字符作为高位，第二个作为地位
			{
				if (ConvertHexChar(pCharBuf[2 * i], &ldata) == 1)
				{
					pByteBuf[i] = (hdata << 4) | ldata;
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}		 
	}
	else
	{
		*bytelen = charlen_tmp >> 1;
		for (i = 0; i < *bytelen; i++)
		{
			if (ConvertHexChar(pCharBuf[2 * i], &hdata) == 1)
			{
				if (ConvertHexChar(pCharBuf[2 * i + 1], &ldata) == 1)
				{
					pByteBuf[i] = (hdata << 4) | ldata;
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
	}	
	return 1;
}

/**********************************************************************************************
	描述：把字符串转换为16进制的数据，以Byte存储
	输入：ch			待处理的字符
	输出：ch_byte   	处理后的数据, Byte类型的
	返回：如果转换成功则返回1，否则返回0
**********************************************************************************************/

S32 ConvertHexChar(S8 ch, U8 *ch_byte)
{
	if ((ch >= '0') && (ch <= '9'))
	{

		*ch_byte = (U8)(ch - 0x30);
		return 1;

	}
	else
	{
		if ((ch >= 'A') && (ch <= 'F'))
		{
			*ch_byte = (U8)(ch - 'A' + 0x0a);
			return 1;
		}
		else
		{
			if ((ch >= 'a') && (ch <= 'f'))
			{
				*ch_byte = (U8)(ch - 'a' + 0x0a);
				return 1;
			}
		}
	}
	return 0;
}

/*
=======================================================================================================================
	描述:把U8类型数组转换成大整数
	输入:
		pByteBuf:U8类型数组
		bytelen:U8类型数组长度
	输出:
		pwBN:U32类型数组,如果bytelen为4的倍数则iBNWordLen至少为bytelen/4,否则为bytelen/4 + 1
		iBNWordLen:大整数pwBN的字数
	返回值:
		0:转换过程错误
		1:转换成功
=======================================================================================================================
*/
S32 ByteToBN(U8 *pByteBuf, S32 bytelen, U32 *pwBN, S32 iBNWordLen)
{
	/*******************/
	S32 ExpLen = 0;
	S32 Rem = 0;
	S32 i = 0;
	S32 j = 0; 
	/*******************/

	ExpLen = bytelen >> 2;//除以4
	Rem = bytelen & 0x00000003;//4的整数倍可表示为二进制最低两位均为00

	if (Rem != 0)//如果bytelen不是4的整数倍
	{
		ExpLen += 1; 
	}

	if (ExpLen > iBNWordLen)
	{
		return 0;
	}

	i = bytelen - 1;
	j = 0;
	while (i >= Rem)
	{
		pwBN[j] = ((U32)pByteBuf[i]) | ((U32)pByteBuf[i - 1] << 8) | ((U32)pByteBuf[i - 2] << 16) | ((U32)pByteBuf[i - 3] << 24);
		i -= 4;
		j++;
	}

	i = 0;
	while (i < Rem)
	{
		pwBN[j] = (pwBN[j] << 8) | ((U32)pByteBuf[i]);//保留上一个，添加新的一个
		i++;
	}

	return 1;
}

/*
=======================================================================================================================
	描述:把大整数转换成U8类型数组
	输入:
		pwBN:U32类型数组
		iBNWordLen:大整数pwBN的字数

	输出:
		pByteBuf:U8类型数组
		bytelen:U8类型数组

	返回值:
		0:转换过程错误
		1:转换成功
=======================================================================================================================
*/
S32 BNToByte(U32 *pwBN,S32 iBNWordLen,U8 *pByteBuf,S32 *bytelen)
{
	/*******************/
	S32 i = 0;
	U8 *P = NULL;
	U32 W = 0;
	/*******************/

	P = pByteBuf;
	for(i = iBNWordLen - 1; i >= 0; i--)	
	{
		W = pwBN[i];
		*P++=(U8) ((W & 0xFF000000) >> 24);//取高八位
		*P++=(U8) ((W & 0x00FF0000) >> 16);
		*P++=(U8) ((W & 0x0000FF00) >> 8);
		*P++=(U8) (W &  0x000000FF) ;
	}
	*bytelen = iBNWordLen << 2;	

	return 1;

}
