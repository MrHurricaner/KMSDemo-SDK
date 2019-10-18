#include "bn.h"
#include "sha2.h"
#include <string.h>
#include <time.h>

/*
=======================================================================================================================
	����:����Ļ����ʾ������
	����:
		pwBN:�����������
		iBNWordLen:����������			
=======================================================================================================================
*/
void BN_Print(U32 *pwBN, S32 iBNWordLen)
{
	/*****************/
	S32 i = 0;
	/*****************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		printf("%08X", pwBN[i]);
	}

	printf("\n");
}

/*
=======================================================================================================================
	����:��������0
	����:pwBN:�����������
		 iBNWordLen:����������			
=======================================================================================================================
*/
void BN_Reset(U32 *pwBN,S32 iBNWordLen)
{
	/*************/
	S32 i = 0;
	/*************/
	
	for (i = 0; i < iBNWordLen; i++)
		pwBN[i] = 0x0;
}

/*
=======================================================================================================================
	����:��������ֵ,pwDest=pwSource
	����:pwDest:����ֵ����
		 pwSource:Դ����
		 iBNWordLen:����������			
=======================================================================================================================
*/

void BN_Assign(U32 *pwDest, U32 *pwSource, S32  iBNWordLen)
{
	/**********/
	S32 i;
	/**********/
	
	for (i = 0; i < iBNWordLen; i++)
		pwDest[i] = pwSource[i];
}

/*
=======================================================================================================================
	����:�жϴ������Ƿ�Ϊ��
	����:pwBN:���жϴ�����	
	����ֵ:0:pwBN��Ϊ��
		   1:pwBNΪ��
=======================================================================================================================
*/
S32 BN_IsZero(U32 *pwBN,S32 iBNWordLen)
{
	/********/
	S32 i;
	/********/

	for (i = 0; i < iBNWordLen; i++)		
		if ( pwBN[i] != 0)		
			return 0;
		return 1;
}

/*
=======================================================================================================================
	����:�жϴ������Ƿ�Ϊ1
	����:pwBN:���жϴ�����	
	����ֵ:0:pwBN��Ϊ1
		   1:pwBNΪ1
=======================================================================================================================
*/
S32 BN_IsOne(U32 *pwBN,S32 iBNWordLen)
{
	/********/
	S32 i = 0;
	/********/

	if (pwBN[0] != LSBOfWord)
	{
		return 0;
	}
	for (i = 1; i < iBNWordLen; i++)	
	{
		if ( pwBN[i] != 0)		
			return 0;
	}
	return 1;
}
/*
=======================================================================================================================
	����:�жϴ������Ƿ�ż��
	����:pwBN:���жϴ�����	
	����ֵ:0:pwBN������
		   1:pwBNΪż��
=======================================================================================================================
*/
S32 BN_IsEven(U32 *pwBN)
{
	if (pwBN[0] & LSBOfWord)		
		return 0;
	return 1;
}

/*
=======================================================================================================================
	����:�жϴ������Ƿ�Ϊ����
	����:pwBN:���жϴ�����	
	����ֵ:0:pwBN������
		   1:pwBNΪż��
=======================================================================================================================
*/
S32 BN_IsOdd(U32 *pwBN)
{
	return	(pwBN[0] & LSBOfWord);
}

/*
=======================================================================================================================
	����:�жϴ������Ƿ����
	����:
		pwX:���жϴ�����1
		pwY:���жϴ�����1
	����ֵ:0:X��Y�����
		   1:X��Y���
=======================================================================================================================
*/
S32 BN_JE(U32 *pwX, U32 *pwY, S32 iBNWordLen)
{
	/*******************/
	S32 i =0;
	/*******************/

	for (i = 0; i < iBNWordLen; i++)
	{
		if (pwX[i] != pwY[i])
		{
			return 0;
		}
	}
	return 1;
}

/*
=======================================================================================================================
	����:�жϴ�����X�Ƿ����Y
	����:
		pwX:���жϴ�����1
		pwY:���жϴ�����1
		iBNWordLen:
	����ֵ:0:X<=Y
		   1:X>Y
=======================================================================================================================
*/
S32 BN_JA(U32 *pwX, U32 *pwY, S32 iBNWordLen)
{
	/*******************/
	S32 i =0;
	/*******************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwX[i] > pwY[i])
		{
			return 1;
		}
		else
		{
			if (pwX[i] < pwY[i])
			{
				return 0;
			}
		}
	}
	return 0;
}

/*
=======================================================================================================================
	����:�õ��������ı�����
	����:
		pwBN:������
		iBNWordLen:������������
=======================================================================================================================
*/
S32 BN_GetBitLen(U32 *pwBN, S32 iBNWordLen)
{
	/***********************/
	S32 i = 0;
	S32 k = 0;
	U32 tmp = 0;
	/***********************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			break;
		}
	}
	if (i == -1)
	{		
		return 0;
	}
	tmp = pwBN[i];
	k = 0;
	while((tmp & MSBOfWord) == 0)	
	{
		tmp = tmp << 1;
		k++;
	}
	return (i  << 5) + (WordLen - k);

}

/*
=======================================================================================================================
	����:�õ��������ı�����
	����:
		pwBN:������
		iBNWordLen:������������
=======================================================================================================================
*/
S32 BN_GetWordLen(U32 *pwBN, S32 iBNWordLen)
{
	/***********************/
	S32 i = 0;
	/***********************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			return i + 1;
		}
	}
	return 0;

}
/*
=======================================================================================================================
	����:�õ�����������Ч��������Чλ��
	����:
		pwBN:������
		iBNWordLen:������������
	���:
		pBitLen:��Ч������
		pU32Len:��Ч����
=======================================================================================================================
*/
void BN_GetLen(S32 *pBitLen, S32 *pU32Len, U32 *pwBN, S32 iBNWordLen)
{
	/***********************/
	S32 i = 0;
	S32 j = 0;
	U32 tmp = 0;
	/***********************/

	*pU32Len = 0;
	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			break;
		}
	}
	if (i == -1)
	{
		*pBitLen = 0;
		*pU32Len = 0;
	}
	else
	{
		j = 0;
		tmp = pwBN[i];
		while ((tmp & MSBOfWord) == 0)
		{
			tmp = tmp << 1;
			j++;
		}
		*pU32Len = i + 1;
		*pBitLen = (i << 5) + (WordLen - j);
	}
}

/*
=======================================================================================================================
	����:�����������ƶ�1����
	����:pwBN:��Ҫ�ƶ������� & �ƶ�֮�����Ĵ洢λ��
		 iBNWordLen:������������
=======================================================================================================================
*/
void BN_ShiftRightOneBit(U32 *pwBN, S32 iBNWordLen)
{
	/**********/
	S32 i;
	/**********/

	for(i = 0; i < iBNWordLen - 1; i++)
	{
		pwBN[i] = (pwBN[i] >> 1) | (pwBN[i + 1] << 31);
	}
	pwBN[i] = pwBN[i] >> 1;
}

/*
=======================================================================================================================
	����:�������������ƶ�1����
	����:pwBN:��Ҫ�ƶ������� & �ƶ�֮�����Ĵ洢λ��
		 iBNWordLen:������������
	����ֵ:����������߱���λ
=======================================================================================================================
*/	
U32 BN_ShiftLeftOneBit(U32 *pwBN, S32 iBNWordLen)
{
	/**************/
	S32 i;
	U32 Carry;
	/**************/
	
	Carry = pwBN[iBNWordLen - 1] & MSBOfWord;
	
	for (i=iBNWordLen-1; i>0; i--)
	{
		pwBN[i] = (pwBN[i] << 1) | (pwBN[i - 1] >> 31);
	}
	
	pwBN[0] = pwBN[0] << 1;
	
	return Carry;
}

/*
=======================================================================================================================
	����:���������,pwSum=pwX+pwY
	����:pwSum:��
		 pwX:������
		 pwY:����
		 iBNWordLen:�������ֳ�
	����ֵ:��λ
=======================================================================================================================
*/	
U32 BN_Add( U32 *pwSum, U32 *pwX, U32 *pwY,S32  iBNWordLen)
{
	/*********************/
    S32 i;
    U64 carry = 0;
	/*********************/
	
	for (i = 0; i < iBNWordLen; i++)
    {
        carry = (U64)pwX[i] + (U64)pwY[i] + carry;
        pwSum[i] = (U32)carry;
        carry = carry >> 32;
    }	
    return (U32)carry;
}

/*
=======================================================================================================================
	����:���������,pwDif=pwX-pwY
	����:pwDiff:��
		 pwX:������
		 pwY:����
		 iBNWordLen:�������ֳ�
	����ֵ:��λ
=======================================================================================================================
*/
U32 BN_Sub(U32 *pwDiff, U32 *pwX, U32 *pwY, S32  iBNWordLen)
{
	/**********************/
    S32 i = 0;
    U64 borrow = 0;
	/**********************/
	
    for (i = 0; i < iBNWordLen; i++)
    {
        borrow = (U64)pwX[i] - (U64)pwY[i] + borrow;
        pwDiff[i] = (U32)borrow;
        borrow = (U64)(((S64)borrow) >> 32);
    }	
    return (U32)borrow;
}
/*
=======================================================================================================================
	����:���������,pwPro=pwX*pwY
	����:
		pwPro:�˻�
		pwX:����
		pwY:������
		iBNWordLen:������X����Y���ֳ�
	����ֵ:��
	Pro���ֳ�����Ϊ2*iBNWordLen
=======================================================================================================================
*/
void BN_Mul(U32 *pwPro, U32 *pwX, U32 *pwY, S32  iBNWordLen)
{
	/*****************/
	S32 i = 0;
	S32 j = 0;
	U64 carry = 0;
	/*****************/

	i = iBNWordLen << 1;
	BN_Reset(pwPro, i);
	for (i = 0; i < iBNWordLen; i++)
	{
		carry = 0;
		for (j = 0; j < iBNWordLen; j++)
		{
			carry = (U64)pwPro[i + j] + (U64)pwX[j] * (U64)pwY[i] + carry;
			pwPro[i + j] = (U32)carry;
			carry >>= WordLen;;
		}
		pwPro[i + iBNWordLen] = (U32)(carry);
	}
}
/*
=======================================================================================================================
	����:������ģ��,pwResult=(pwX+pwY) mod pwModule
	����:pwResult:���
		 pwX:����1
		 pwY:����2
		 pwModule:ģ
		 iBNWordLen:�������ֳ�
	ע:T=2^(iBNWordLen*32)  X<T,Y<T,R<T,Result<T
=======================================================================================================================
*/
void BN_ModAdd(U32 *pwResult, U32 *pwX, U32 *pwY, U32 *pwModule, S32  iBNWordLen)
{
    U32 c = 0;
	
    c = BN_Add(pwResult, pwX, pwY,iBNWordLen);
	
    if (c == 0)
        return;
    do
    {
        c = BN_Sub(pwResult, pwResult, pwModule,iBNWordLen);
    } while (c==0);	
}

/*
=======================================================================================================================
	����:������ģ��,pwResult=(pwX-pwY) mod pwModule
	����:pwResult:���
		 pwX:������
		 pwY:����
		 pwModule:ģ
		 iBNWordLen:�������ֳ�
	ע:T=2^(iBNWordLen*32)  X<T,Y<T,R<T,Result<T
=======================================================================================================================
*/
void BN_ModSub(U32 *pwResult, U32 *pwX, U32 *pwY, U32 *pwModule, S32  iBNWordLen)
{
    U32 c = 0;
	
    c = BN_Sub(pwResult, pwX, pwY,iBNWordLen);
	
    if (c == 0)
        return;
    do
    {
        c = BN_Add(pwResult, pwResult, pwModule,iBNWordLen);

    } while (c == 0);	
}

/*
=======================================================================================================================
	����:����������,	pwR=pwa^-1 mod pwm
	����:
		pwa:������
		pwm:������,ģ
		iBNWordLen:���������ֳ�
	���:
		pwResult:������pwa^-1 mod pwm
	ע��:����pwm����Ϊ����,pwa < pwm
=======================================================================================================================
*/
S32 BN_GetInv(U32 *pwResult, U32 *pwa, U32 *pwm, S32 iBNWordLen)
{
	/*********************************/
	U32 u[PaiBNWordLen];
	U32 v[PaiBNWordLen];
	U32 A[PaiBNWordLen];
	U32 C[PaiBNWordLen];
	U32 carry = 0;
	/*********************************/

	/* A=1, C=0, u=a, v=p */
	BN_Reset(A, PaiBNWordLen);
	BN_Reset(C, PaiBNWordLen);
	BN_Reset(u, PaiBNWordLen);
	BN_Reset(v, PaiBNWordLen);
	A[0]=1;
	BN_Assign(u, pwa, iBNWordLen);
	BN_Assign(v, pwm, iBNWordLen);

	while(!BN_IsZero(u, iBNWordLen))
	{
		while(!BN_IsOdd(u))
		{
			carry = 0;
			BN_ShiftRightOneBit(u, iBNWordLen);
			if(BN_IsOdd(A))
			{
				carry = BN_Add(A, A, pwm, iBNWordLen);
			}
			BN_ShiftRightOneBit(A, iBNWordLen);			
			if (carry == 1)
			{
				A[iBNWordLen - 1] |= MSBOfWord;
			}			
		}

		while(!BN_IsOdd(v))
		{
			carry = 0;
			BN_ShiftRightOneBit(v, iBNWordLen);
			if(BN_IsOdd(C))
			{
				carry = BN_Add(C, C, pwm, iBNWordLen);
			}
			BN_ShiftRightOneBit(C, iBNWordLen);			
			if (carry == 1)
			{
				C[iBNWordLen - 1] |= MSBOfWord;
			}			
		}
		
		if (BN_JA(v, u, iBNWordLen))
		{
			BN_Sub(v, v, u, iBNWordLen);
			BN_ModSub(C, C, A, pwm, iBNWordLen);
		}
		else
		{
			BN_Sub(u, u, v, iBNWordLen);
			BN_ModSub(A, A, C, pwm, iBNWordLen);
		}

	}
	if (BN_IsOne(v, iBNWordLen) == 0)
	{
		return 0;
	}
	BN_Assign(pwResult, C, iBNWordLen);
	return 1;
}

/*
=======================================================================================================================
	����:Montgomery�����㷨��pwInv = pwBN ^ {-1} * R mod pwModule
	����:
		pwBN:������Ĵ�����,�ֳ�ΪiBNWordLen
		pwModule:ģ,�ֳ�ΪiBNWordLen
		wModuleConst:Montgomeryģ�˳���
		pwRRModule: ������R^2 mod pwModule
		iBNWordLen:���������ֳ���λ��������BNWordLen
	���:
		pwInv:��Ԫ,pwInv = pwBN ^ {-1} * R mod pwModule
	ע�⣺���������pwBN��������ʾ����������Montgomery��ʾ������
=======================================================================================================================
*/
void BN_GetInv_Mont(U32 *pwInv,			//ģ����
			   U32 *pwBN,			//��Ҫ���������
			   U32 *pwModule,       //ģ��
			   U32 wModuleConst,    //monmul�˷���ģ���Ĳ���MC
			   U32 *pwRRModule,      //ģ���Ĳ���RR
			   S32 iBNWordLen
			   )
{
	U32 bn_u[BNWordLen + 1],bn_v[BNWordLen + 1],bn_s[BNWordLen + 1];
	U32 bn_a[BNWordLen + 1],bn_ainv[BNWordLen + 1];
	int int_k=0,int_m,i,j,int_cofainv;

	int_m = iBNWordLen*WordByteLen*8;

	BN_Assign(bn_a,pwBN,iBNWordLen);

	//Phase I
	for(i = 0; i < iBNWordLen; i++)
	{
		bn_u[i] = 0;
		bn_v[i] = 0;
		bn_s[i] = 0;
		bn_ainv[i] = 0;
	}

	BN_Assign(bn_u,pwModule,iBNWordLen);
	BN_Assign(bn_v,bn_a,iBNWordLen);
	bn_s[0] = 1;

	while(!BN_IsZero(bn_v,iBNWordLen))
	{
		if(!(bn_u[0]&LSBOfWord))
		{
			BN_ShiftRightOneBit(bn_u,iBNWordLen);
			BN_ShiftLeftOneBit(bn_s,iBNWordLen);
		}
		else if(!(bn_v[0]&LSBOfWord))
		{
			BN_ShiftRightOneBit(bn_v,iBNWordLen);
			BN_ShiftLeftOneBit(bn_ainv,iBNWordLen);
		}
		else if(BN_JA(bn_u,bn_v,iBNWordLen)==1)
		{
			BN_Sub(bn_u,bn_u,bn_v,iBNWordLen);
			BN_ShiftRightOneBit(bn_u,iBNWordLen);
			BN_Add(bn_ainv,bn_ainv,bn_s,iBNWordLen);
			BN_ShiftLeftOneBit(bn_s,iBNWordLen);
		}
		else if(!(BN_JA(bn_u,bn_v,iBNWordLen)==1))
		{
			BN_Sub(bn_v,bn_v,bn_u,iBNWordLen);
			BN_ShiftRightOneBit(bn_v,iBNWordLen);
			BN_Add(bn_s,bn_s,bn_ainv,iBNWordLen);
			int_cofainv=BN_ShiftLeftOneBit(bn_ainv,iBNWordLen);
		}
		int_k++;
	}
	if((!(BN_JA(pwModule,bn_ainv,iBNWordLen)==1))|int_cofainv)
		BN_Sub(bn_ainv,bn_ainv,pwModule,iBNWordLen);
	BN_Sub(bn_ainv,pwModule,bn_ainv,iBNWordLen);

	//Phase II
	if(int_k <= int_m)
	{
		BN_ModMul_Mont(bn_ainv,bn_ainv,pwRRModule,pwModule,wModuleConst,iBNWordLen);
		int_k = int_k + int_m;
	}
	for(i = 0; i < iBNWordLen; i++)
		bn_u[i] = 0;

	j = (2*int_m -int_k) / (WordByteLen*8);
	bn_u[j] = 1;
	for(i = 0; i < (2*int_m-int_k) % (WordByteLen*8); i++)
		bn_u[j] = bn_u[j] << 1;
	
	BN_ModMul_Mont(pwInv,bn_ainv,bn_u,pwModule,wModuleConst,iBNWordLen);
}
/*
=======================================================================================================================
	����:�õ�Montgomeryģ������Ҫ�ĳ���
	����:
		nLastU32:�����������һ����
		nRadix: �ݴ�
		���:
		n' = -n0 ^ (-1) mod 2 ^ nRadix
=======================================================================================================================
*/
U32 BN_GetMontConst(U32 nLastU32, S32 nRadix)
{
	U64 y = 0;
	U64 tmp = 0;
	U64 flag_2_i = 0;
	U64 flag_last_i = 0;
	S32 i = 0;

	y = 1;
	flag_2_i = 1;
	flag_last_i = 1;
	for ( i = 2; i <= nRadix; i++ )
	{
		flag_2_i = flag_2_i << 1;
		flag_last_i = (flag_last_i << 1) | 0x01;
		tmp = nLastU32 * y;
		tmp = tmp & flag_last_i;
		if ( tmp > flag_2_i)
		{
			y = y + flag_2_i;
		}
	}
	flag_2_i = flag_2_i << 1;

	return (U32)(flag_2_i - y);
}

/*
=======================================================================================================================
	����:Montgomeryģ��
	����:
		pwX:������X,�ֳ�λiBNWordLen
		pwY:������Y,�ֳ�ΪiBNWordLen
		pwM:������M,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:���������ֳ���λ��������BNWordLen
		wModuleConst: monmul�˷���ģ���Ĳ���MC
	���:
		pwResult:ģ�˽��,�ֳ��ֳ�ΪiBNWordLen
=======================================================================================================================
*/
void BN_ModMul_Mont(U32 *pwResult,		//monmul���
			  U32 *pwX,			//����1
			  U32 *pwY,			//����2
			  U32 *pwModule,		//ģ��
			  U32 wModuleConst,     //monmul�˷���ģ���Ĳ���MC
			  S32 iBNWordLen
			  )
{
	int i, j;
	U64 carry;
	U32 U;
	U32 D[BNMAXWordLen + 2];
	
	BN_Reset(D, BNMAXWordLen + 2);
	
	for (i = 0; i < iBNWordLen; i++)
	{
		carry = 0;
		for (j = 0; j < iBNWordLen; j++)
		{
			carry = (U64)D[j] + (U64)pwX[j] * (U64)pwY[i] + carry;
			D[j] = (U32)carry;
			carry = carry >> 32;
		}
		
		carry = (U64)D[iBNWordLen] + carry;
		D[iBNWordLen] = (U32)carry;
		D[iBNWordLen + 1] = (U32)(carry >> 32);
		
		carry = (U64)D[0] * (U64)wModuleConst;
		U = (U32)carry;
		carry = (U64)D[0] + (U64)U * (U64)pwModule[0];
		carry = carry >> 32;
		for (j = 1; j < iBNWordLen; j++)
		{
			carry = (U64)D[j] + (U64)U * (U64)pwModule[j] + carry;
			D[j - 1] = (U32)carry;
			carry = carry >> 32;
		}
		carry = (U64)D[iBNWordLen] + carry;
		D[iBNWordLen - 1] = (U32)carry;
		D[iBNWordLen] = D[iBNWordLen + 1] + (U32)(carry >> 32);
	}
	if (D[iBNWordLen] == 0)
		BN_Assign(pwResult,D, iBNWordLen);
	else
		BN_Sub(pwResult, D, pwModule, iBNWordLen);
}

void BN_ModSqu_Mont(U32 *pwResult,		//monmul���
					U32 *pwX,			//����1
					U32 *pwModule,		//ģ��
					U32 wModuleConst,     //monmul�˷���ģ���Ĳ���MC
					S32 iBNWordLen
			  )
{
	BN_ModMul_Mont(pwResult, pwX, pwX, pwModule, wModuleConst, iBNWordLen);
}

/*
=======================================================================================================================
����:������ģ������pwResult = pwX ^ pxE mod pwM
����:
pwX:������X,�ֳ�λiBNWordLen
pwE:������Y,�ֳ�ΪiBNWordLen
pwM:������M,ģ,�ֳ�ΪiBNWordLen
iBNWordLen:���������ֳ���λ��������BNWordLen
���:
pwResult:ģ�ݽ��,�ֳ��ֳ�ΪiBNWordLen
=======================================================================================================================
*/
void BN_ModExp(U32 *pwResult, U32 *pwX, U32 *pwE, U32 *pwM, U32 wModuleConst, S32 iBNWordLen)
{
	S32 bitlen = 0;
	S32 i = 0;
	U32 flag[32] = {0x00000001,0x00000002,0x00000004,0x00000008,
		0x00000010,0x00000020,0x00000040,0x00000080,
		0x00000100,0x00000200,0x00000400,0x00000800,
		0x00001000,0x00002000,0x00004000,0x00008000,
		0x00010000,0x00020000,0x00040000,0x00080000,
		0x00100000,0x00200000,0x00400000,0x00800000,
		0x01000000,0x02000000,0x04000000,0x08000000,
		0x10000000,0x20000000,0x40000000,0x80000000};

	bitlen = BN_GetBitLen(pwE, iBNWordLen);
	if (bitlen == 0)
	{
		BN_Reset(pwResult, iBNWordLen);
		pwResult[0] = LSBOfWord;

	}
	else
	{		
		BN_Assign(pwResult, pwX, iBNWordLen);		
		for (i = bitlen - 2; i >= 0; i--)
		{
			//BN_ModMul_Stand(pwResult, pwResult, pwResult, pwM, iBNWordLen);
			BN_ModSqu_Mont(pwResult, pwResult, pwM, wModuleConst, iBNWordLen);
			if (pwE[i / WordLen] & flag[i % WordLen])
				//BN_ModMul_Stand(pwResult, pwResult, pwX, pwM, iBNWordLen);
				BN_ModMul_Mont(pwResult, pwResult, pwX, pwM, wModuleConst, iBNWordLen);
		}
	}
}

/*
=======================================================================================================================
	����:�����������
	����:
		pwBN:������X,�ֳ�λiBNWordLen
		iBNWordLen:����������Ч�ֳ�
=======================================================================================================================
*/
void BN_Random(U32 *pwBN, S32 iBNWordLen)
{
	/*******************/
	S32 i = 0, j = 0;
	U8 B0 = 0;
	U8 B1 = 0;
	U8 B2 = 0;
	U8 B3 = 0;
	U8 data[8] = {0};
	U8 digest[32] = {0};
	sha256_context ctx;
	/*******************/

	for (i = 0; i < iBNWordLen; i++)
	{
		//B0 = (U8)rand();
		//B1 = (U8)rand();
		//B2 = (U8)rand();
		//B3 = (U8)rand();
		//pwBN[i] = ((U32)B3 << 24) | ((U32)B3 << 16) | ((U32)B3 << 8) | ((U32)B3);

		for (j = 0; j < 8; j++)
		{
			data[j] = (U8)rand();
		}
		sha256_starts(&ctx);
		sha256_update(&ctx, data, 8);
		sha256_finish(&ctx, digest);
		pwBN[i] = ((U32)digest[0] << 24) | ((U32)digest[1] << 16) | ((U32)digest[2] << 8) | ((U32)digest[3]);
	}
}

/*
=======================================================================================================================
	����:������������ȡģ
	����:
		pwBN:������X,�ֳ�λiBNWordLen
		pwMod:������M,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:���������ֳ���λ��������BNWordLen
	���:
		pwBN:ģ�˽��,�ֳ��ֳ�ΪiBNWordLen
=======================================================================================================================
*/
void BN_GetLastRes(U32 *pwBN, U32 *pwMod, S32 iBNWordLen)
{
    while ( BN_JA(pwMod, pwBN, iBNWordLen) == 0)
    {
        BN_Sub(pwBN, pwBN, pwMod, iBNWordLen);
    }
}





/*
=======================================================================================================================
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,����Ҫ��pwBNM[l-1]>=2^(w-1),����lΪpwBNM������
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���MAXBNWordLen-2
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen_M
		iBNWordLen_M:pwBNM���ֳ�
		iBWordLen_q:quo���ֳ�,����ΪiBNWordLen_X��iBNWordLen_M+1
	���:
		quo:��,�ֳ��ֳ�����ΪiBNWordLen_q		
		rem:����,�ֳ�����ΪiBNWordLen_r,
=======================================================================================================================
*/
S32 BN_Div_Basic(U32 *rem, U32 *quo, U32 *pwBNX, S32 iBNWordLen_X, U32 *pwBNM, S32 iBNWordLen_M)
{	
	/******************************/
	S32 i = 0;
	S32 j = 0;
	U64 q = 0;
	U64 carry = 0;
	U64 tmp = 0;
	S32 k = 0;
	S32 l = 0;
	S32 ll = 0;
	S32 len_rem = 0;
	U32 temp[BNMAXWordLen];
	U32 quo_tmp[BNMAXWordLen];
	/******************************/

	BN_Reset(temp, BNMAXWordLen);
	BN_Reset(quo_tmp, BNMAXWordLen);
	k = iBNWordLen_X;
	l = iBNWordLen_M;
	ll = l - 1;
	for (i = k - l; i >= 0; i--)
	{
		q = ((((U64)(pwBNX[i + l]) << WordLen) + (U64)pwBNX[i + l - 1]))/(U64)pwBNM[ll];//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
		if(q & 0xffffffff00000000)//���q[i]>=B-1
			quo_tmp[i] = 0xffffffff;
		else
			quo_tmp[i] = (U32)q;
		carry = 0;
		for(j = 0; j < l; j++)//temp = q[i] * pwBNM
		{
			carry = (U64)quo_tmp[i] * ( U64)pwBNM[j] + carry;
			temp[j] = (U32)carry;
			carry >>= WordLen;
		}
		temp[j] = (U32)carry;
		carry = 0;
		for(j = 0; j < l; j++)//pwBNX = pwBNX - (temp << ( 32 * i))
		{
			carry = (U64)pwBNX[i+j] - (U64)temp[j] + carry;
			pwBNX[i+j] = (U32) carry;
			carry = ((S64)carry) >> WordLen;				
		}
		carry = (U64)pwBNX[i+j] - (U64)temp[j] + carry;
		while(carry & 0x1000000000000000)//while r[i+l] < 0
		{
			tmp = 0;
			for(j = 0; j < l; j++)//pwBNX = pwBNX + (pwBNM << ( 32 * i))
			{
				tmp = (U64)pwBNX[i+j] + (U64)pwBNM[j]+tmp;
				pwBNX[i + j] = (U32)tmp;
				tmp = (U64)(tmp >> WordLen);		
			}
			carry = carry + tmp;
			quo_tmp[i] -= 1;
		}
		pwBNX[i + l] = (U32)carry;
	}
	BN_Assign(quo, quo_tmp, BNMAXWordLen);

	len_rem = BN_GetWordLen(pwBNX, iBNWordLen_M);
	if (len_rem > iBNWordLen_M)//�ж�rem��λ���Ƿ�����
		return 0;
	BN_Assign(rem, pwBNX, len_rem);
	return 1;
}


/*
=======================================================================================================================
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,��Ҫ�Ƕ����ݽ�������ʹ֮����BN_Mod_Basic���������
		 ����,��������BN_Div_Basic�����ݽ��д���,���Եõ��Ľ������У�����Ӷ��õ����ս��.
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���PaiWordLen
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:pwBNM,quo,rem���ֳ�
	���:
		quo:��,�ֳ��ֳ�ΪiBNWordLen
		rem:����,�ֳ��ֳ�ΪiBNWordLen
=======================================================================================================================
*/
S32 BN_Div(U32 *pwResult,  U32 *quo, U32 *pwBNX, S32 iBNWordLen_X, U32 *pwBNM,  S32 iBNWordLen_M)
{
	/*~~~~~~~~~~~~~~~~~~~*/
	S32 wordlen_x = 0;
	S32 wordlen_m = 0;
	U32 temp = 0;
	S32 i = 0;
	S32 shiftbit = 0;
	U32 temp_pwx[BNMAXWordLen];
	U32 temp_pwm[BNMAXWordLen];
	S32 result = 0;
	/*~~~~~~~~~~~~~~~~~~~*/

	wordlen_x = BN_GetWordLen(pwBNX, iBNWordLen_X);
	if (wordlen_x > 64)//ֻ֧��λ��������2048���ص�ȡģ����
	{
		return 0;
	}
	wordlen_m = BN_GetWordLen(pwBNM, iBNWordLen_M);
	if (wordlen_m > 64)
	{		
		return 0;
	}
	BN_Reset(temp_pwx, BNMAXWordLen);
	BN_Reset(temp_pwm, BNMAXWordLen);
	BN_Assign(temp_pwx, pwBNX, wordlen_x);
	BN_Assign(temp_pwm, pwBNM, wordlen_m);
	temp = temp_pwm[wordlen_m - 1];
	
	while (temp < MSBOfWord)//������Ҫ���ƶ���λ������ʹ������ִ���2^(w-1)
	{
		temp <<= 1;
		shiftbit++;
	}
	for (i = 0; i < shiftbit; i++)//ʹtemp_pwm��������������2^(w-1)
	{
		BN_ShiftLeftOneBit(temp_pwx, wordlen_x + 1);
		BN_ShiftLeftOneBit(temp_pwm, wordlen_m);
	}
	if (temp_pwx[wordlen_x] != 0)//�õ�temp_pwx������
		wordlen_x += + 1;
	BN_Reset(pwResult, iBNWordLen_M);
	result = BN_Div_Basic(pwResult, quo, temp_pwx, wordlen_x, temp_pwm, wordlen_m);//����BN_Mod_Basic����
	if (result == 0)
		return 0;
	for (i = 0; i < shiftbit; i++)
	{
		BN_ShiftRightOneBit(pwResult, wordlen_m);
	}
	return 1;
}
/*
=======================================================================================================================
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,����Ҫ��pwBNM[l-1]>=2^(w-1),����lΪpwBNM������
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���MAXBNWordLen-2
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen_M
		iBNWordLen_M:pwBNM���ֳ�
		iBWordLen_q:quo���ֳ�,����ΪiBNWordLen_X��iBNWordLen_M+1
	���:
		quo:��,�ֳ��ֳ�����ΪiBNWordLen_q		
		rem:����,�ֳ�����ΪiBNWordLen_r,
=======================================================================================================================
*/
S32 BN_Mod_Basic(U32 *rem, S32 iBNWordLen_r, U32 *pwBNX, S32 iBNWordLen_X, U32 *pwBNM, S32 iBNWordLen_M)
{	
	/******************************/
	S32 i = 0;
	S32 j = 0;
	U64 q = 0;
	U64 carry = 0;
	U64 tmp = 0;
	S32 k = 0;
	S32 l = 0;
	S32 ll = 0;
	S32 len_rem = 0;
	U32 temp[BNMAXWordLen];
	U32 quo_tmp[BNMAXWordLen];
	/******************************/

	BN_Reset(temp, BNMAXWordLen);
	BN_Reset(quo_tmp, BNMAXWordLen);
	k = iBNWordLen_X;
	l = iBNWordLen_M;
	ll = l - 1;
	//PC[20181113]-TODO: i = k - l,��bug��Ӧ��Ϊi = k - l - 1;��Ȼ���ڴ�Խ��
	for (i = k - l; i >= 0; i--)
	{
		q = ((((U64)(pwBNX[i + l]) << WordLen) + (U64)pwBNX[i + l - 1]))/(U64)pwBNM[ll];//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
		if(q & 0xffffffff00000000)//���q[i]>=B-1
			quo_tmp[i] = 0xffffffff;
		else
			quo_tmp[i] = (U32)q;
		carry = 0;
		for(j = 0; j < l; j++)//temp = q[i] * pwBNM
		{
			carry = (U64)quo_tmp[i] * ( U64)pwBNM[j] + carry;
			temp[j] = (U32)carry;
			carry >>= WordLen;
		}
		temp[j] = (U32)carry;
		carry = 0;
		for(j = 0; j < l; j++)//pwBNX = pwBNX - (temp << ( 32 * i))
		{
			carry = (U64)pwBNX[i+j] - (U64)temp[j] + carry;
			pwBNX[i+j] = (U32) carry;
			carry = ((S64)carry) >> WordLen;				
		}
		carry = (U64)pwBNX[i+j] - (U64)temp[j] + carry;
		while(carry & 0x1000000000000000)//while r[i+l] < 0
		{
			tmp = 0;
			for(j = 0; j < l; j++)//pwBNX = pwBNX + (pwBNM << ( 32 * i))
			{
				tmp = (U64)pwBNX[i+j] + (U64)pwBNM[j]+tmp;
				pwBNX[i + j] = (U32)tmp;
				tmp = (U64)(tmp >> WordLen);		
			}
			carry = carry + tmp;
			quo_tmp[i] -= 1;
		}
		pwBNX[i + l] = (U32)carry;
	}
	len_rem = BN_GetWordLen(pwBNX, iBNWordLen_M);
	if (len_rem > iBNWordLen_r)//�ж�rem��λ���Ƿ�����
		return 0;
	BN_Assign(rem, pwBNX, len_rem);
	return 1;
}

/*
=======================================================================================================================
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,��Ҫ�Ƕ����ݽ�������ʹ֮����BN_Mod_Basic���������
		 ����,��������BN_Div_Basic�����ݽ��д���,���Եõ��Ľ������У�����Ӷ��õ����ս��.
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���PaiWordLen
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:pwBNM,quo,rem���ֳ�
	���:
		quo:��,�ֳ��ֳ�ΪiBNWordLen
		rem:����,�ֳ��ֳ�ΪiBNWordLen
=======================================================================================================================
*/
S32 BN_Mod(U32 *pwResult,  S32 iBNWordLen_r, U32 *pwBNX, S32 iBNWordLen_X, U32 *pwBNM,  S32 iBNWordLen_M)
{
	/*~~~~~~~~~~~~~~~~~~~*/
	S32 wordlen_x = 0;
	S32 wordlen_m = 0;
	U32 temp = 0;
	S32 i = 0;
	S32 shiftbit = 0;
	U32 temp_pwx[BNMAXWordLen];
	U32 temp_pwm[BNMAXWordLen];
	S32 result = 0;
	/*~~~~~~~~~~~~~~~~~~~*/

	wordlen_x = BN_GetWordLen(pwBNX, iBNWordLen_X);
	if (wordlen_x > 64)//ֻ֧��λ��������2048���ص�ȡģ����
	{
		return 0;
	}
	wordlen_m = BN_GetWordLen(pwBNM, iBNWordLen_M);
	if (wordlen_m > 64)
	{		
		return 0;
	}
	BN_Reset(temp_pwx, BNMAXWordLen);
	BN_Reset(temp_pwm, BNMAXWordLen);
	BN_Assign(temp_pwx, pwBNX, wordlen_x);
	BN_Assign(temp_pwm, pwBNM, wordlen_m);
	temp = temp_pwm[wordlen_m - 1];
	
	while (temp < MSBOfWord)//������Ҫ���ƶ���λ������ʹ������ִ���2^(w-1)
	{
		temp <<= 1;
		shiftbit++;
	}
	for (i = 0; i < shiftbit; i++)//ʹtemp_pwm��������������2^(w-1)
	{
		BN_ShiftLeftOneBit(temp_pwx, wordlen_x + 1);
		BN_ShiftLeftOneBit(temp_pwm, wordlen_m);
	}
	if (temp_pwx[wordlen_x] != 0)//�õ�temp_pwx������
		wordlen_x += + 1;
	BN_Reset(pwResult, iBNWordLen_r);
	result = BN_Mod_Basic(pwResult, iBNWordLen_r, temp_pwx, wordlen_x, temp_pwm, wordlen_m);//����BN_Mod_Basic����
	if (result == 0)
		return 0;
	for (i = 0; i < shiftbit; i++)
	{
		BN_ShiftRightOneBit(pwResult, wordlen_m);
	}
	return 1;
}
/**
���ܣ���ȡ
*/
void BN_GetR(U32 *pwR, U32 *pwX, S32 iBNWordLen)
{
	U32 BNT[BNMAXWordLen];

	BN_Reset(BNT, BNMAXWordLen);

	BN_Sub(pwR, BNT, pwX, iBNWordLen);//R = 0-N;
}

void BN_GetR2(U32 *pwR2, U32 *pwR, U32 *pwModule, U32 wModuleConst, S32 iBNWordLen, S32 iLogLogBNWordLen)
{
	U32 BN_T1[BNMAXWordLen];
	U32 BN_T2[BNMAXWordLen];

	S32 i = 0;

	BN_Reset(BN_T1, BNMAXWordLen);
	BN_Reset(BN_T2, BNMAXWordLen);

	BN_ModAdd(BN_T1, pwR, pwR, pwModule, iBNWordLen);//BN_T1 = 2*R

	for ( i = 0; i < iLogLogBNWordLen; i ++ )
	{
		BN_ModMul_Mont(BN_T2, BN_T1, BN_T1, pwModule, wModuleConst, iBNWordLen);//
		BN_Assign(BN_T1, BN_T2, iBNWordLen);
	}

	BN_Assign(pwR2, BN_T2, iBNWordLen);
}
/*
=======================================================================================================================
����:������ȡģ����
����:
pwBN:���������ֳ�λiBNWordLen
iBNWordLen:pwBNX���ֳ�,���ܳ���PaiBNWordLen
n:ģ,32��������
���:
pResult:���
=======================================================================================================================
*/
void BN_ModWord(U32 *pResult, U32 *pwBN, S32 iBNWordLen, U32 n)
{
	/********************************/
	S32 shiftbit = 0;
	S32 shiftbit2 = 0;
	S32 wordlen = 0;
	S32 k = 0;
	U32 rem[Ext_PaiBNWordLen];//֧��1024���صĴ���������
	U32 quo[Ext_PaiBNWordLen];
	U32 temp[2];
	S32 i = 0;
	U32 n_tmp = 0;
	U64 carry = 0;
	U64 tmp = 0;
	U64 q = 0;
	/********************************/

	for (i = 0; i < Ext_PaiBNWordLen; i++)
	{
		rem[i] = 0;
		quo[i] = 0;
	}
	temp[0] = 0;
	temp[1] = 0;
	wordlen = BN_GetWordLen(pwBN, iBNWordLen);
	BN_Assign(rem, pwBN, wordlen);

	n_tmp = n;
	while (n_tmp != 0)
	{
		n_tmp >>= 1;
		shiftbit++;
	}
	shiftbit2 = shiftbit;
	shiftbit = WordLen - shiftbit;

	n_tmp = (n << shiftbit);
	for (i = wordlen; i > 0; i--)//����rem
	{
		rem[i] = (rem[i] << shiftbit) | (rem[i - 1] >> shiftbit2);
	}
	rem[0] <<= shiftbit;

	if (rem[wordlen] != 0)
	{
		k = wordlen + 1;
	}
	else
	{
		k = wordlen;
	}

	for (i = k - 1; i >= 0; i--)
	{
		q = ((((U64)(rem[i + 1]) << WordLen) + (U64)rem[i]))/(U64)n_tmp;//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
		if(q & 0xffffffff00000000)//���q[i]>=B-1
			quo[i] = 0xffffffff;
		else
			quo[i] = (U32)q;

		carry = (U64)quo[i] * ( U64)n_tmp;
		temp[0] = (U32)carry;
		carry >>= WordLen;
		temp[1] = (U32)carry;

		carry = (U64)rem[i] - (U64)temp[0];
		rem[i] = (U32)carry;
		carry = ((S64)carry) >> WordLen;

		carry = (U64)rem[i + 1] - (U64)temp[1] + carry;
        
        time_t start_t, end_t;
        double diff_t;
        time(&start_t);
        
        
		while (carry & 0x1000000000000000)//while r[i+l] < 0
		{
			tmp = (U64)rem[i] + (U64)n_tmp;
			rem[i] = (U32)tmp;
			tmp = (U64)(tmp >> WordLen);
			carry = carry + tmp;
			quo[i] -= 1;
		}
		rem[i + 1] = (U32)carry;
        
        time(&end_t);
        diff_t = difftime(end_t, start_t);
//        printf("Execution time = %f\n", diff_t);
        if (diff_t > 1) {
            printf("took over %f seconds\n",diff_t);
        }
        
	}
	*pResult = rem[0] >> shiftbit;
}
/*
���ܣ��жϴ������Ƿ�Ϊ����
���룺���жϴ�����
�����1��ʾΪ������0��ʾ������
*/
S32 BN_PrimeTest(U32 *pwBN, S32 iBNWordLen)
{
	/*******************************/
	U32 wModuleConst = 0;
	S32 wordlen = 0;
	S32 bitlen = 0;
	S32 counter = 0;
	S32 i = 0;
	S32 j = 0;
	S32 r = 0;
	S32 flag = 0;
	S32 loglen = 0;

	U32 a[BNMAXWordLen];
	U32 n_1[BNMAXWordLen];
	U32 m[BNMAXWordLen];
	U32 q[BNMAXWordLen];
	U32 tmp[BNMAXWordLen];
	U32 BN_R[BNMAXWordLen];
	U32 BN_R2[BNMAXWordLen];
	/*******************************/

	BN_Reset(n_1, BNMAXWordLen);
	BN_Reset(a, BNMAXWordLen);
	BN_Reset(m, BNMAXWordLen);
	BN_Reset(q, BNMAXWordLen);
	BN_Reset(tmp, BNMAXWordLen);
	BN_Reset(BN_R, BNMAXWordLen);
	BN_Reset(BN_R2, BNMAXWordLen);

	tmp[0] = LSBOfWord;
	BN_Sub(n_1, pwBN, tmp, iBNWordLen);
	BN_Assign(m, n_1, iBNWordLen);//m=n-1
	while (BN_IsEven(m))
	{
		BN_ShiftRightOneBit(m, iBNWordLen);
		i++;
	}

	wModuleConst = BN_GetMontConst(pwBN[0], 32);
	BN_GetR(BN_R, pwBN, iBNWordLen);
	loglen = (S32)(log(32*iBNWordLen)/log(2));
	BN_GetR2(BN_R2, BN_R, pwBN, wModuleConst, iBNWordLen, loglen);

	for (r = 0; r < 20; r++)
	{
		BN_Random(a, iBNWordLen);
		BN_ModMul_Mont(a, a, BN_R2, pwBN, wModuleConst, iBNWordLen);
		BN_ModExp(q, a, m, pwBN, wModuleConst, iBNWordLen);
		BN_ModMul_Mont(q, q, tmp, pwBN, wModuleConst, iBNWordLen);
		BN_GetLastRes(q, pwBN, iBNWordLen);

		if (BN_JE(q, n_1, iBNWordLen) || BN_IsOne(q, iBNWordLen))
		{
			continue;
		}
		flag = 0;
		for ( j = 0; j < i - 1; j++)
		{
			BN_ModMul_Mont(q, q, BN_R2, pwBN, wModuleConst, iBNWordLen);
			BN_ModSqu_Mont(q, q, pwBN, wModuleConst, iBNWordLen);
			BN_ModMul_Mont(q, q, tmp, pwBN, wModuleConst, iBNWordLen);
			BN_GetLastRes(q, pwBN, iBNWordLen);

			if (BN_JE(q, n_1, iBNWordLen))//q=n-1
			{
				flag = 1;
				break;
			}
			else
			{
				if (BN_IsOne(q, iBNWordLen))//q=1
				{
					return 0;
				}
			}
		}
		if (flag == 0)
		{
			return 0;
		}		
	}
	return 1;
}
/*
���ܣ�����һ���̶����ȵ�����
���룺����
�������Ӧ���ȵ�����
*/
void BN_GenPrime(U32 *pwBN, S32 iBNWordLen)
{
	/**************************/
	S32 i = 0;
	U32 carry = 0;
	U32 bi = 0;
	S32 gp = 0;
	U8 flag[1024];
	U32 n[MAXPrimeWordLen];
	U32 n_tmp[MAXPrimeWordLen];
	U32 tmp[MAXPrimeWordLen];
	/**************************/

	BN_Reset(n, MAXPrimeWordLen);
	BN_Reset(n_tmp, MAXPrimeWordLen);
	BN_Reset(tmp, MAXPrimeWordLen);
	while (1)
	{
		BN_Random(n, iBNWordLen);//���������n
		n[0] |= LSBOfWord;
		n[iBNWordLen - 1] |= MSBOfWord;

		memset( flag, 0, 1024 );
		for (i = 0; i < 100; i++)//����С��������ɸѡ
		{
			BN_ModWord(&bi, n, iBNWordLen, (U32)primetable[i]);
			if (bi == 0)
			{
				gp = 0;
			}
			else
			{
				if (bi & LSBOfWord)
				{
					gp = ((U32)primetable[i] - bi) >> 1;//gp = (p - r) / 2
				}
				else
				{
					gp = (((U32)primetable[i] << 1) - bi) >> 1;//gp = (2p - r) / 2
				}
			}
			while ( gp < 1024)
			{
				flag[gp] = 1;
				gp += (U32)primetable[i];
			}					
		}

		for (i = 0; i < 1024; i++)
		{
			if ( flag[i] == 0)
			{
				tmp[0] = ((U32)i) << 1;
				carry = BN_Add(n_tmp, n, tmp, iBNWordLen);
				/*
				if ( carry != 0)
				{
				break;
				}
				*/
				if (BN_PrimeTest(n_tmp, iBNWordLen) == 1)
				{
					BN_Assign(pwBN, n_tmp, iBNWordLen);
					return;
				}					
			}				
		}
	}
}
