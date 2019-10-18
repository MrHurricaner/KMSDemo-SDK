#include <stdio.h>
#include <string.h>
#include "ecdsa_test.h"
#include "ecdsa.h"
#include "common.h"

void ECDSA_KeyGen_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	//S8 *charbuf_prikey = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";
	//S8 *charbuf_pubkey = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	S8 *charbuf_prikey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	S8 *charbuf_pubkey = "2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE64564B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085";

	U8 bytebuf_prikey[32];
	U8 bytebuf_pubkey[64];
	U8 bytebuf_tmpkey[64];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	//得到标准PriKey
	charlen = 64;
	result = CharToByte(charbuf_prikey, charlen, bytebuf_prikey, &bytelen);

	//得到标准PubKey
	charlen = 128;
	result = CharToByte(charbuf_pubkey, charlen, bytebuf_pubkey, &bytelen);

	result = ECDSA_KeyGen(bytebuf_tmpkey, &m_SECP256K1_Sys_Para, bytebuf_prikey);

	if ((result == 1) && !memcmp(bytebuf_tmpkey, bytebuf_pubkey, 64))
	{
		printf("The testing of ECDSA_KeyGen_Test is right!\n");
	}
	else
	{
		printf("The testing of ECDSA_KeyGen_Test is wrong!\n");
	}
}


void ECDSA_Sign_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	S8 *charbuf_prikey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	S8 *charbuf_pubkey = "2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE64564B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085";
	S8 *charbuf_hash = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	S8 *charbuf_rand = "882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4";
	S8 *charbuf_sign = "432D36AD7C15F289D193D233332B4192EC52182354661263962826D8D53BC7E89675EA52B268E2A4EC21DC1DC136EB2029CD8F5F0EDA24F5A159F136B9C128E4";

	U8 bytebuf_prikey[32];
	U8 bytebuf_pubkey[64];
	U8 bytebuf_hash[32];
	U8 bytebuf_rand[32];
	U8 bytebuf_sign[64];
	U8 bytebuf_temp[64];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	result = CharToByte(charbuf_prikey, 64, bytebuf_prikey, &bytelen);//得到标准PriKey
	result = CharToByte(charbuf_pubkey, 128, bytebuf_pubkey, &bytelen);//得到标准PubKey
	result = CharToByte(charbuf_hash, 64, bytebuf_hash, &bytelen);//得到标准Hash
	result = CharToByte(charbuf_rand, 64, bytebuf_rand, &bytelen);//得到标准Rand
	result = CharToByte(charbuf_sign, 128, bytebuf_sign, &bytelen);//得到标准Sign

	result = ECDSA_Sign(bytebuf_temp, &m_SECP256K1_Sys_Para, bytebuf_hash, bytebuf_prikey, bytebuf_rand);

	if ((result == 1) && !memcmp(bytebuf_temp, bytebuf_sign, 64))
	{
		printf("The testing of ECDSA_Sign_Test is right!\n");
	}
	else
	{
		printf("The testing of ECDSA_Sign_Test is wrong!\n");
	}
}


void ECDSA_Verify_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	S8 *charbuf_prikey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	S8 *charbuf_pubkey = "2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE64564B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085";
	S8 *charbuf_hash = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	S8 *charbuf_rand = "882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4";
	S8 *charbuf_sign = "432D36AD7C15F289D193D233332B4192EC52182354661263962826D8D53BC7E89675EA52B268E2A4EC21DC1DC136EB2029CD8F5F0EDA24F5A159F136B9C128E4";
	S8 *charbuf_wrong = "432D36AD7C25F289D193D233332B4192EC52182354661263962826D8D53BC7E89675EA52B268E2A4EC21DC1DC136EB2029CD8F5F0EDA24F5A159F136B9C128E4";


	U8 bytebuf_prikey[32];
	U8 bytebuf_pubkey[64];
	U8 bytebuf_hash[32];
	U8 bytebuf_rand[32];
	U8 bytebuf_sign[64];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	result = CharToByte(charbuf_prikey, 64, bytebuf_prikey, &bytelen);//得到标准PriKey
	result = CharToByte(charbuf_pubkey, 128, bytebuf_pubkey, &bytelen);//得到标准PubKey
	result = CharToByte(charbuf_hash, 64, bytebuf_hash, &bytelen);//得到标准Hash
	result = CharToByte(charbuf_rand, 64, bytebuf_rand, &bytelen);//得到标准Rand
	result = CharToByte(charbuf_sign, 128, bytebuf_sign, &bytelen);//得到标准Sign

	result = ECDSA_Verify(&m_SECP256K1_Sys_Para, bytebuf_hash, bytebuf_pubkey, bytebuf_sign);

	if (result == 1)
	{
		printf("The testing of ECDSA_Verify_Test(For right) is right!\n");
	}
	else
	{
		printf("The testing of ECDSA_Verify_Test(For right) is wrong!\n");
	}

	result = CharToByte(charbuf_wrong, 128, bytebuf_sign, &bytelen);//得到标准Sign

	result = ECDSA_Verify(&m_SECP256K1_Sys_Para, bytebuf_hash, bytebuf_pubkey, bytebuf_sign);
	if (result != 1)
	{
		printf("The testing of ECDSA_Verify_Test(For wrong) is right!\n");
	}
	else
	{
		printf("The testing of ECDSA_Verify_Test(For wrong) is wrong!\n");
	}
}

void ECDSA_Sign_Verify_Random_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	U8 bytebuf_prikey[32];
	U8 bytebuf_pubkey[64];
	U8 bytebuf_hash[32];
	U8 bytebuf_rand[32];
	U8 bytebuf_sign[64];
	U32 BNT[8];

	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	S32 i = 0;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);


	for ( i = 0; i < 32; i++ )
	{
		bytebuf_prikey[i] = 0x00;
		bytebuf_pubkey[i] = 0x00;
		bytebuf_pubkey[i + 32] = 0x00;
		bytebuf_hash[i] = 0x00;
		bytebuf_rand[i] = 0x00;
		bytebuf_sign[i] = 0x00;
		bytebuf_sign[i + 32] = 0x00;
	}	
	BN_Reset(BNT, 8);

	for ( i = 0; i < 100; i++ )
	{
		printf("i = %d\n", i);

		//产生临时密钥对
		result = ECDSA_KeyGen(bytebuf_pubkey, &m_SECP256K1_Sys_Para, bytebuf_prikey);

		//产生随机数
		BN_Random(BNT, 8);
		BNToByte(BNT, 8, bytebuf_rand, &bytelen);

		//产生随机的hash值
		BN_Random(BNT, 8);
		BNToByte(BNT, 8, bytebuf_hash, &bytelen);

		//产生签名
		result = ECDSA_Sign(bytebuf_sign, &m_SECP256K1_Sys_Para, bytebuf_hash, bytebuf_prikey, bytebuf_rand);

		//验证签名
		result = ECDSA_Verify(&m_SECP256K1_Sys_Para, bytebuf_hash, bytebuf_pubkey, bytebuf_sign);
		if (result != 1)
		{
			printf("The testing of ECDSA_Verify_Test is right!\n");
		}
		else
		{
			printf("The testing of ECDSA_Verify_Test is wrong!\n");
			break;
		}

	}

	
	
	
	

}