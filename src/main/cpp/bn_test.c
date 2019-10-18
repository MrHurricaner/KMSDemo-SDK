#include "bn_test.h"
#include "bn.h"
#include <memory.h>
#include <stdio.h>

void BN_Print_Test()
{
	/*******************/
	U32 BN_tmp[BNWordLen];
	S32 i = 0;
	/*******************/

	BN_Reset(BN_tmp, BNWordLen);

	for (i = 0; i < BNWordLen; i ++)
	{
		BN_tmp[i] = 0x01234567;
	}

	BN_Print(BN_tmp, BNWordLen);

}

void BN_GetBitlen_Test()
{
	/********************/
	U32 BN_X[BNWordLen];
	S32 BitLen = 0;
	/********************/

	BN_Reset(BN_X, BNWordLen);
	BitLen = BN_GetBitLen(BN_X, BNWordLen);
	if (BitLen == 0)
	{
		printf("The testing of BN_GetBitLen is right, when BN is zero!");
	}
	else
	{
		printf("The testing of BN_GetBitLen is wrong, when BN is zero!");
	}

	BN_Reset(BN_X, BNWordLen);
	BN_X[0] = 0x123;
	BitLen = BN_GetBitLen(BN_X, BNWordLen);
	if (BitLen == 9)
	{
		printf("The testing of BN_GetBitLen is right, when BN has less than 32 bits!");
	}
	else
	{
		printf("The testing of BN_GetBitLen is wrong, when BN has less than 32 bits!");
	}

	BN_Reset(BN_X, BNWordLen);
	BN_X[0] = 0x12345678;
	BN_X[1] = 0x12345678;
	BN_X[2] = 0x12345678;
	BN_X[3] = 0x8;
	BitLen = BN_GetBitLen(BN_X, BNWordLen);
	if (BitLen == 100)
	{
		printf("The testing of BN_GetBitLen is right, when BN has larger than 32 bits!");
	}
	else
	{
		printf("The testing of BN_GetBitLen is wrong, when BN has larger than 32 bits!");
	}
}

void BN_GetLen_Test()
{
	/********************/
	U32 BN_X[BNWordLen];
	S32 BitLen_tmp = 0;
	S32 WordLen_tmp = 0;
	/********************/

	BN_Reset(BN_X, BNWordLen);
	BN_GetLen(&BitLen_tmp, &WordLen_tmp, BN_X, BNWordLen);
	if (BitLen_tmp != 0)
	{
		printf("The testing of BN_GetBitLen is wrong, when BN is zero!\n");
	}
	else
	{
		printf("The testing of BN_GetBitLen is right, when BN is zero!\n");
	}

	BN_Reset(BN_X, BNWordLen);
	BN_X[0] = 0x123;
	BN_GetLen(&BitLen_tmp, &WordLen_tmp, BN_X, BNWordLen);
	if (BitLen_tmp == 9)
	{
		printf("The testing of BN_GetBitLen is right, when BN has less than 32 bits!\n");
	}
	else
	{
		printf("The testing of BN_GetBitLen is wrong, when BN has less than 32 bits!\n");
	}

	BN_X[0] = 0x12345678;
	BN_X[1] = 0x12345678;
	BN_X[2] = 0x12345678;
	BN_X[3] = 0x8;
	BN_GetLen(&BitLen_tmp, &WordLen_tmp, BN_X, BNWordLen);
	if (BitLen_tmp == 100)
	{
		printf("The testing of BN_GetBitLen is right, when BN has larger than 32 bits!\n");
	}
	else
	{
		printf("The testing of BN_GetBitLen is wrong, when BN has larger than 32 bits!\n");
	}
}

void BN_ModAdd_Test()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_R[BNWordLen];
	U32 BN_Stand[BNWordLen];

//	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";
	S8 *charbuf_m = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";  //椭圆曲线的

	//Case 0(0 Subduction)
//	S8 *charbuf_x0 = "60E9551B9988DF5272260B4A329B3745FEFC0CE997AC77C7FF53D00E58872048";
//	S8 *charbuf_y0 = "70CCE4BB249BBB0675C6F8BAF34890A8BD3FA04A9812CEDC77160B5B074BB420";
//	S8 *charbuf_r0 = "D1B639D6BE249A58E7ED040525E3C7EEBC3BAD342FBF46A47669DB695FD2D468";

	//  sk1 + sk2 = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
	//	S8 *charbuf_psk_1 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	//	S8 *charbuf_psk_2 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_x0 = "91929491211981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_y0 = "88998998899883FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_r0 = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";


	//Case 1(1 Subduction)
	S8 *charbuf_x1 = "889C58386527188CEB2F35F235F91FA815E1EC845F64B818BB295A70811652D6";
	S8 *charbuf_y1 = "A28EFD6C72B59F477119522734B5F9BB5294ACB7A5E1C953D2E456DFF305CC7A";
	S8 *charbuf_r1 = "74EB55A4D53910E28644DCC97520521E468405F0EACB9290A89E162890CAD9D3";

	//Case 2(2 Subduction)
	S8 *charbuf_x2 = "E4B1B8BD32A7E72CD5D51BF92F35289C1EF9131B2F8BA284ABA8E2533D4988BB";
	S8 *charbuf_y2 = "F15970F15F4177692DA9E57F68C04A702D800D9815CAE9001526866747EB22A1";
	S8 *charbuf_r2 = "698B29AE8CA210B25777AAD8ACD7E4820893FA1D1060ADCCF5F0326ABE922062";

	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);
	BN_Reset(BN_Stand, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_r0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	BN_ModAdd(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_R, BNWordLen))
	{
		printf("The testing of BN_ModAdd: Case 0 is right!\n");
	}
	else
	{
		BN_Print(BN_R, BNWordLen);
		printf("The testing of BN_ModAdd: Case 0 is wrong!\n");
		return;
	}

	BN_Print(BN_R, BNWordLen);


	//Case 1
	charlen = 64;;
	result = CharToByte(charbuf_x1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_r1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	BN_ModAdd(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_R, BNWordLen))
	{
		printf("The testing of BN_ModAdd: Case 1 is right!\n");
	}
	else
	{
		printf("The testing of BN_ModAdd: Case 1 is wrong!\n");
		return;
	}

	BN_Print(BN_R, BNWordLen);


	//Case 2
	charlen = 64;;
	result = CharToByte(charbuf_x2, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y2, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_r2, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	BN_ModAdd(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_R, BNWordLen))
	{
		printf("The testing of BN_ModAdd: Case 2 is right!\n");
	}
	else
	{
		printf("The testing of BN_ModAdd: Case 2 is wrong!\n");
		return;
	}

	BN_Print(BN_R, BNWordLen);
}

void BN_ModSub_Test()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_R[BNWordLen];
	U32 BN_Stand[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";

	//Case 0(0 Addition)
//	S8 *charbuf_x0 = "E7933E845253E808990A81E00D2C0443F6F505392A29E6916A53128A5B6E5E9C";
//	S8 *charbuf_y0 = "5B3472D55740B0938241A245B0F95667DEA6A679C2A41C10E6BFE4F511780CE2";
//	S8 *charbuf_r0 = "8C5ECBAEFB13377516C8DF9A5C32ADDC184E5EBF6785CA8083932D9549F651BA";


//  sk1 + sk2 = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
//	S8 *charbuf_psk_1 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
//	S8 *charbuf_psk_2 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_x0 = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	S8 *charbuf_y0 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_r0 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";


	//Case 1(0 Addition)
	S8 *charbuf_x1 = "60E9551B9988DF5272260B4A329B3745FEFC0CE997AC77C7FF53D00E58872048";
	S8 *charbuf_y1 = "70CCE4BB249BBB0675C6F8BAF34890A8BD3FA04A9812CEDC77160B5B074BB420";
	S8 *charbuf_r1 = "A65C70607790CB3DD262BDDF34E16DE263AEFFEA1A1497C76DAD5FDB348CB1A5";


	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);
	BN_Reset(BN_Stand, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_r0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	BN_ModSub(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_R, BNWordLen))
	{
		printf("The testing of BN_ModSub: Case 0 is right!\n");
	}
	else
	{
		printf("The testing of BN_ModSub: Case 0 is wrong!\n");
		return;
	}

	BN_Print(BN_R, BNWordLen);


	//Case 1
	charlen = 64;;
	result = CharToByte(charbuf_x1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_r1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	BN_ModSub(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_R, BNWordLen))
	{
		printf("The testing of BN_ModSub: Case 1 is right!\n");
	}
	else
	{
		printf("The testing of BN_ModSub: Case 1 is wrong!\n");
		return;
	}

	BN_Print(BN_R, BNWordLen);
}


void BN_ModMul_Mont_Test()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_Res[BNWordLen];
	U32 BN_Stand[BNWordLen];
	U32 BN_One[BNWordLen];
	U32 BN_RR[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";

	U32 wModuleConst = 0x2F2EE42B;

	//R= 10000000000000000000000000000000000000000000000000000000000000000
	// = 49BFFFFFFD5C590E29FC54B00A7138BADE0D6CB4E58511241A9064D81CAEBA83
	S8 *charbuf_x = "E7933E845253E808990A81E00D2C0443F6F505392A29E6916A53128A5B6E5E9C";
	S8 *charbuf_y = "5B3472D55740B0938241A245B0F95667DEA6A679C2A41C10E6BFE4F511780CE2";
	S8 *charbuf_s = "228814751405FE005D5E09C113F1789C858498AD0C33A188CFF3105D1A1678FE";
	S8 *charbuf_rr = "2EA795A656F62FBDE479B522D6706E7B88F8105FAE1A5D3F27DEA312B417E2D2";//R^2 mod M

	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_RR, BNWordLen);
	BN_Reset(BN_Res, BNWordLen);
	BN_Reset(BN_Stand, BNWordLen);
	BN_Reset(BN_One, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_x, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_y, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_s, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_rr, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_RR, BNWordLen);

	//One
	BN_One[0] = 0x00000001;

	//X_Mont = X * R mod M
	BN_ModMul_Mont(BN_X, BN_X, BN_RR, BN_M, wModuleConst, BNWordLen);

	//Y_Mont = Y * R mod M
	BN_ModMul_Mont(BN_Y, BN_Y, BN_RR, BN_M, wModuleConst, BNWordLen);

	BN_ModMul_Mont(BN_Res, BN_X, BN_Y, BN_M, wModuleConst, BNWordLen);//X*Y*R  mod M
	BN_ModMul_Mont(BN_Res, BN_Res, BN_One, BN_M, wModuleConst, BNWordLen);//X*Y  mod M
	BN_GetLastRes(BN_Res, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_Res, BNWordLen))
	{
		printf("The testing of BN_ModMul_Mont is right!\n");
	}
	else
	{
		printf("The testing of BN_ModMul_Mont is wrong!\n");
	}

	BN_Print(BN_Res, BNWordLen);
}

void BN_GetInv_Mont_Test()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_Res[BNWordLen];
	U32 BN_Stand[BNWordLen];
	U32 BN_One[BNWordLen];
	U32 BN_RR[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";

	U32 wModuleConst = 0x2F2EE42B;

	//R= 10000000000000000000000000000000000000000000000000000000000000000
	// = 49BFFFFFFD5C590E29FC54B00A7138BADE0D6CB4E58511241A9064D81CAEBA83
	S8 *charbuf_x = "E7933E845253E808990A81E00D2C0443F6F505392A29E6916A53128A5B6E5E9C";
	S8 *charbuf_s = "52734BDB29A470C5EA6C7E114B0DF557180873F821E5C0E3F5BB49523A5388AA";
	S8 *charbuf_rr = "2EA795A656F62FBDE479B522D6706E7B88F8105FAE1A5D3F27DEA312B417E2D2";//R^2 mod M

	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_RR, BNWordLen);
	BN_Reset(BN_Res, BNWordLen);
	BN_Reset(BN_Stand, BNWordLen);
	BN_Reset(BN_One, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_x, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_s, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Stand, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_rr, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_RR, BNWordLen);

	//One
	BN_One[0] = 0x00000001;

	BN_GetInv_Mont(BN_Res, BN_X, BN_M, wModuleConst, BN_RR, BNWordLen);//X^(-1)*R  mod M
	BN_ModMul_Mont(BN_Res, BN_Res, BN_One, BN_M, wModuleConst, BNWordLen);//X^(-1)  mod M
	BN_GetLastRes(BN_Res, BN_M, BNWordLen);

	if (BN_JE(BN_Stand, BN_Res, BNWordLen))
	{
		printf("The testing of BN_ModMul_Mont is right!\n");
	}
	else
	{
		printf("The testing of BN_ModMul_Mont is wrong!\n");
	}

	BN_Print(BN_Res, BNWordLen);
}


/*
功能：获得常数R
*/
void BN_GetR_Test()
{
	/*******************************/
	S8 *str_n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	U32 BN_Q[BNWordLen];
	U32 BN_R[BNWordLen];
	U32 BN_R2[BNWordLen];
	U32 wModuleConst;
	U8 bytebuf[150];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/**********************/
	wModuleConst = 0;
	BN_Reset(BN_Q, BNWordLen);
	BN_Reset(BN_R, BNWordLen);
	BN_Reset(BN_R2, BNWordLen);

	charlen = 64;
	result = CharToByte(str_n, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Q, BNWordLen);
	BN_GetR(BN_R, BN_Q, BNWordLen);
	BN_Print(BN_R, BNWordLen);

	wModuleConst = BN_GetMontConst(BN_Q[0], 32);
	printf("%02X\n", wModuleConst);
	//获得R^2
	BN_GetR2(BN_R2, BN_R, BN_Q, wModuleConst, BNWordLen, 8);
	BN_Print(BN_R2, BNWordLen);
}






void BN_ModAdd_Test_cd()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_R[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";

	S8 *charbuf_x0 = "AEEAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_y0 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_r0 = "E1AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";


	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	BN_ModAdd(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	BN_Print(BN_R, BNWordLen);
}

void BN_ModSub_Test_cd()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_R[BNWordLen];
	U32 BN_Stand[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";


	S8 *charbuf_x0 = "AEEAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_y0 = "AC264D80078772E3AC2A18CA933E436A2E8AAC5B521C834F98D5D718AB767D93";
	S8 *charbuf_r0 = "02C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";


	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);


	BN_ModSub(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	BN_Print(BN_R, BNWordLen);


	S8 *charbuf_x1 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_y1 = "B6EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_r1 = "3219B27FFB1C340E29D99285625083DAF367E6EFC85E6B8C4C99C40F37DAC7EA";


	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);


	BN_ModSub(BN_R, BN_X, BN_Y, BN_M, BNWordLen);

	BN_Print(BN_R, BNWordLen);
}


void BN_Modkkk_Test_cd()
{
	/*******************/
	U32 BN_X[BNWordLen];
	U32 BN_Y[BNWordLen];
	U32 BN_X1[BNWordLen];
	U32 BN_Y1[BNWordLen];
	U32 BN_M[BNWordLen];
	U32 BN_R[BNWordLen];
	U32 BN_R0[BNWordLen];
	U32 BN_R1[BNWordLen];

	S8 *charbuf_m = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";

	S8 *charbuf_x0 = "AC264D80078772E3AC2A18CA933E436A2E8AAC5B521C834F98D5D718AB767D93";
	S8 *charbuf_y0 = "02C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_x1 = "B6EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_y1 = "3219B27FFB1C340E29D99285625083DAF367E6EFC85E6B8C4C99C40F37DAC7EA";


	U8 bytebuf[200];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 result = 0;
	/*******************/

	BN_Reset(BN_X, BNWordLen);
	BN_Reset(BN_Y, BNWordLen);
	BN_Reset(BN_X1, BNWordLen);
	BN_Reset(BN_Y1, BNWordLen);
	BN_Reset(BN_M, BNWordLen);
	BN_Reset(BN_R, BNWordLen);
	BN_Reset(BN_R0, BNWordLen);
	BN_Reset(BN_R1, BNWordLen);

	charlen = 64;
	result = CharToByte(charbuf_m, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_M, BNWordLen);


	//Case 0
	charlen = 64;;
	result = CharToByte(charbuf_x0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y0, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_x1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_X1, BNWordLen);

	charlen = 64;;
	result = CharToByte(charbuf_y1, charlen, bytebuf, &bytelen);
	result = ByteToBN(bytebuf, bytelen, BN_Y1, BNWordLen);

	BN_ModAdd(BN_R0, BN_Y1 , BN_Y, BN_M, BNWordLen);
	BN_ModAdd(BN_R1, BN_X , BN_R0, BN_M, BNWordLen);
	BN_ModAdd(BN_R, BN_R1, BN_X1, BN_M, BNWordLen);

	BN_Print(BN_R, BNWordLen);
}

