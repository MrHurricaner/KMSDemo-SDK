#include "common.h"

/*
=======================================================================================================================
	����:��S8��������ת����U8��������
	����:
		pCharBuf:S8�������飬Ϊ'0'-'9'��'a'-'f'��'A'-'F',��������򷵻�0
		charlen:S8�������鳤��
	���:
		pByteBuf:U8��������,���charlenΪ����,pByteBuf��������Ϊcharlen/2+1,��������Ϊcharlen/2
		bytelen:U8�������鳤��,
	����ֵ:
		0:ת�����̴���
		1:ת���ɹ�
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
	if (charlen_tmp & LSBOfWord)//���charlen������
	{
		charlen_tmp += 1;
		*bytelen = charlen_tmp >> 1;
		if (ConvertHexChar(pCharBuf[0], &ldata) == 1)//���������һλ
		{
			pByteBuf[0] = ldata;
		}
		for (i = 1; i < *bytelen; i++)
		{
			if (ConvertHexChar(pCharBuf[2 * i - 1], &hdata) == 1)//��һ���ַ���Ϊ��λ���ڶ�����Ϊ��λ
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
	���������ַ���ת��Ϊ16���Ƶ����ݣ���Byte�洢
	���룺ch			��������ַ�
	�����ch_byte   	����������, Byte���͵�
	���أ����ת���ɹ��򷵻�1�����򷵻�0
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
	����:��U8��������ת���ɴ�����
	����:
		pByteBuf:U8��������
		bytelen:U8�������鳤��
	���:
		pwBN:U32��������,���bytelenΪ4�ı�����iBNWordLen����Ϊbytelen/4,����Ϊbytelen/4 + 1
		iBNWordLen:������pwBN������
	����ֵ:
		0:ת�����̴���
		1:ת���ɹ�
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

	ExpLen = bytelen >> 2;//����4
	Rem = bytelen & 0x00000003;//4���������ɱ�ʾΪ�����������λ��Ϊ00

	if (Rem != 0)//���bytelen����4��������
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
		pwBN[j] = (pwBN[j] << 8) | ((U32)pByteBuf[i]);//������һ��������µ�һ��
		i++;
	}

	return 1;
}

/*
=======================================================================================================================
	����:�Ѵ�����ת����U8��������
	����:
		pwBN:U32��������
		iBNWordLen:������pwBN������

	���:
		pByteBuf:U8��������
		bytelen:U8��������

	����ֵ:
		0:ת�����̴���
		1:ת���ɹ�
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
		*P++=(U8) ((W & 0xFF000000) >> 24);//ȡ�߰�λ
		*P++=(U8) ((W & 0x00FF0000) >> 16);
		*P++=(U8) ((W & 0x0000FF00) >> 8);
		*P++=(U8) (W &  0x000000FF) ;
	}
	*bytelen = iBNWordLen << 2;	

	return 1;

}
