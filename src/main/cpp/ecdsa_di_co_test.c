#include <stdio.h>
#include <string.h>

#include "common.h"
#include "ecdsa_di_co.h"

#include "cela_rand.h"


extern void ECDSA_DiCo_Multiplier_Pre(U8 *pbPK, U8 *pbSK, S32 iBNWordLen);

extern void ECDSA_DiCo_Multiplier_C1(U8 *pbBN_C1,
	U8 *pbBN_a, U32 *pwMod, S32 iModWordLen,
	U8 *pbPK, U8 *pbRand, S32 iBNWordLen);

extern void ECDSA_DiCo_Multiplier_C2_and_Beta(U8 *pbBN_C2, U8 *pbBN_beta,
	U8 *pbBN_b, U32 *pwMod, S32 iModWordLen,
	U8 *pbBN_C1, U8 *pbPK, U8 *pbRand, S32 iBNWordLen);

extern void ECDSA_DiCo_Multiplier_Alpha(U8 *pbBN_alpha,
	U32 *pwMod, S32 iModWordLen,
	U8 *pbBN_C2, U8 *pbSK, S32 iBNWordLen);

void ECDSA_DiCo_Multiplier_Test()
{
	S8 *charbuf_k1 = "882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4";
	S8 *charbuf_p1 = "31A10DD1B9CCD87518B9A4F3281269EA849EAC929FDCEC47FDFD3B786E934600";
	S8 *charbuf_n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	S8 *charbuf_kp = "763B1F20467E6214B62FD5E729CA1BB827471E2A133C9D2B7BD3E0790598CA55";


	S8 *charbuf_r1 = "EBA1FA088C19AFA1F6D93447BA4DD396389AA9F238148C81C1FFDB6BB4014E623D34F21DD865C7314392685D0FB6A60C31727952ACECC785A0DE08E73DF5E054FA72E85C7C9B2606FC167A10735A9F1E155B66A7F31449D6624EF9D4354CFD3B2B5C70E34AC8FBC209B818B047DC3A7D474A4A519381074D71E6BAC6D7E3E57A";
	S8 *charbuf_r2 = "6D304A56691E7F282CFBECEA98D23E59660EFA5A877868850300F8967CB7BB9F18BC2F24A5E953489487354CC4BFA812017AC78489C50F7D840F9112BDD5264A973999D41B2463C0AC98E98157F8688CC73D76ABEB5B38DDCDD11FCEC4CD033215826F5BBEA1854E8DFA53E5BB8F04AAF77042F9B810F4AB5984327DD21D943F1DE4C20F1C42B20356AEEA7F7C84D29B8396F994830BA72FD67843BFC2069D60";

	U8 bytebuf_k1[32];
	U8 bytebuf_p1[32];
	U8 bytebuf_n[32];
	U8 pbPK[256], pbSK[384];
	U8 pbC1[256], pbC2[256];
	U8 pbR1[128], pbR2[160];
	U8 pbAlpha[32], pbBeta[32], pbMul[32];

	U32 bnA[8], bnB[8], bnM[8], bnC[8], bnT[8];
	S32 bytelen;
	S32 ret;
	//int i;

	ret = CharToByte(charbuf_k1, 64, bytebuf_k1, &bytelen);
	ret = CharToByte(charbuf_p1, 64, bytebuf_p1, &bytelen);
	ret = CharToByte(charbuf_n, 64, bytebuf_n, &bytelen);
	ret = CharToByte(charbuf_kp, 64, pbMul, &bytelen);
	ret = CharToByte(charbuf_r1, 256, pbR1, &bytelen);
	ret = CharToByte(charbuf_r2, 320, pbR2, &bytelen);

	ByteToBN(bytebuf_n, 32, bnM, 8);

	ECDSA_DiCo_Multiplier_Pre(pbPK, pbSK, 32);


	ECDSA_DiCo_Multiplier_C1(pbC1, bytebuf_k1, bnM, 8, pbPK, pbR1, 32);

	ECDSA_DiCo_Multiplier_C2_and_Beta(pbC2, pbBeta, bytebuf_p1, bnM, 8, pbC1, pbPK, pbR2, 32);

	ECDSA_DiCo_Multiplier_Alpha(pbAlpha, bnM, 8, pbC2, pbSK, 32);

	//printf("ECDSA_DiCo_Multiplier的公钥PK：\n");
	//for (i = 0; i < 128; i++)
	//{
	//	printf("%02X", pbPK[i]);
	//}
	//printf("\n");

	//printf("ECDSA_DiCo_Multiplier的私钥SK：\n");
	//for (i = 0; i < 384; i++)
	//{
	//	printf("%02X", pbSK[i]);
	//}
	//printf("\n");

	//printf("ECDSA_DiCo_Multiplier的输出Alpha：\n");
	//for (i = 0; i < 32; i++)
	//{
	//	printf("%02X", pbAlpha[i]);
	//}
	//printf("\n");

	//printf("ECDSA_DiCo_Multiplier的输出Beta：\n");
	//for (i = 0; i < 32; i++)
	//{
	//	printf("%02X", pbBeta[i]);
	//}
	//printf("\n");

	ByteToBN(pbAlpha, 32, bnA, 8);
	ByteToBN(pbBeta, 32, bnB, 8);
	ByteToBN(pbMul, 32, bnC, 8);

	BN_ModAdd(bnT, bnA, bnB, bnM, 8);


	if (BN_JE(bnT, bnC, 8))
	{
		printf("The testing of ECDSA_DiCo_Multiplier_Test is right!\n");
	}
	else
	{
		printf("The testing of ECDSA_DiCo_Multiplier_Test is wrong!\n");
	}

}

void ECDSA_DiCo_KeyGen_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	S8 *charbuf_psk_1 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_psk_2 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_ppk_1 = "28BF5A13FDAED86AA46E4A3402D0893537EC22050A6002959FDB7EEE1CD7629C2D4361205A4D513C6240D71982379ECE780B90037E3C0B33FFD04ADC6461B535";
	S8 *charbuf_ppk_2 = "340C2EAC661082CF068912CDDFB46269C9044CD44B1B486B492EE4C44971762034001F2D8760B0392ABBF3582B0A75277FC9AC9FA1A7F78688F8E09F52D74832";
	S8 *charbuf_pubkey = "2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE64564B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085";

	U8 pb_P1_SK[32];
	U8 pb_P2_SK[32];
	U8 pb_P1_PK[64];
	U8 pb_P2_PK[64];
	U8 pbPubKey[64];

	U8 pbMultSK[384];
	U8 pbMultPK[128];

	U8 pb_ZK_R1[32];
	U8 pb_ZK_R2[32];
	U8 pb_P1_ZK[64];
	U8 pb_P2_ZK[64];
	
	U8 pbTmpKey[64];
	U8 pbTmp_PK[64];

	S32 charlen = 0;
	S32 bytelen = 0;
	S32 ret = 0;
	int flag = 0;
	int i;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	//得到标准数据
	ret = CharToByte(charbuf_psk_1, 64, pb_P1_SK, &bytelen);
	ret = CharToByte(charbuf_psk_2, 64, pb_P2_SK, &bytelen);
	ret = CharToByte(charbuf_ppk_1, 128, pb_P1_PK, &bytelen);
	ret = CharToByte(charbuf_ppk_2, 128, pb_P2_PK, &bytelen);
	ret = CharToByte(charbuf_pubkey, 128, pbPubKey, &bytelen);

	//P1 Proof
	ret = ECDSA_DiCo_KeyGen_P1_Send(pbMultSK, pbMultPK, pbTmpKey, pb_P1_ZK, &m_SECP256K1_Sys_Para, pb_P1_SK, pb_ZK_R1);
	if ((ret != 1) || 
		(memcmp(pbTmpKey, pb_P1_PK, 64) != 0))
	{
		flag++;
	}

	//P2 Proof and Verify
	ret = ECDSA_DiCo_KeyGen_P2_Done(pbTmp_PK, pbTmpKey, pb_P2_ZK, &m_SECP256K1_Sys_Para, pbMultPK, pb_P2_SK, pb_P1_PK, pb_P1_ZK, pb_ZK_R2);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, pb_P2_PK, 64) != 0) ||
		(memcmp(pbTmp_PK, pbPubKey, 64) != 0))
	{
		flag++;
	}

	//P1 Verify
	ret = ECDSA_DiCo_KeyGen_P1_Recv(pbTmp_PK, &m_SECP256K1_Sys_Para, pbMultPK, pb_P1_SK, pb_P1_PK, pb_P2_PK, pb_P2_ZK);
	if ((ret != 1) ||
		(memcmp(pbTmp_PK, pbPubKey, 64) != 0))
	{
		flag++;
	}

	if (flag)
	{
		printf("The testing of ECDSA_DiCo_KeyGenTest is wrong!\n");
	}
	else
	{
		printf("The testing of ECDSA_DiCo_KeyGenTest is right!\n");
		printf("ECDSA_DiCo_Multiplier的公钥PK：\n");
		for (i = 0; i < 128; i++)
		{
			printf("%02X", pbMultPK[i]);
		}
		printf("\n");

		printf("ECDSA_DiCo_Multiplier的私钥SK：\n");
		for (i = 0; i < 384; i++)
		{
			printf("%02X", pbMultSK[i]);
		}
		printf("\n");
	}
}

void ECDSA_DiCo_Sign_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	S8 *charbuf_hash = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	S8 *charbuf_sign = "432D36AD7C15F289D193D233332B4192EC52182354661263962826D8D53BC7E89675EA52B268E2A4EC21DC1DC136EB2029CD8F5F0EDA24F5A159F136B9C128E4";


	//sk1 + sk2 = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
	S8 *charbuf_psk_1 = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
	S8 *charbuf_psk_2 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
	S8 *charbuf_pubkey = "2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE64564B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085";

	S8 *charbuf_multpk = "5B7C1CBE0328CE73E0B305575CF1861A9FB74EE6703274B6E5D5C5B50580FC78FCCC1B6A0731DC87FE32669A5D154D85C47AB0E789623B140B8E919467819C9459A36E272170BFBC0A1928663F7AB527E4822069ABA7A332184B7ED5337EC9CB9DBFE2A15894D12FF68A1D61A8015AB36013C795BBF93699AA178428380E62C1";
	S8 *charbuf_multsk = "5B7C1CBE0328CE73E0B305575CF1861A9FB74EE6703274B6E5D5C5B50580FC78FCCC1B6A0731DC87FE32669A5D154D85C47AB0E789623B140B8E919467819C9325EFBA726BBB0A0708172663A4E01A8E6502A0E99F9B97264F82B60C66B1FCFF15375A18306CA9078D20B3F8B71069C23BEFA3713A77B51833A10DB27C52A5841519B778AB2D3E8333F15F0136ED6B9A7D89BEFEC343BFC227E3420B400AC4F06B24BC613CB2A70A1C9D0C09D1C6316558A6661B198817820019EB9E96F352C36BF8EB12354E6F44D856E59E69DDCCDFF59534BD627DC3A5EC8C6C92ADC9080E0919A6178D10781C08852AA7BECFDEA737BDB870E809B86051F9490128D68F275B7C1CBE0328CE73E0B305575CF1861A9FB74EE6703274B6E5D5C5B50580FC78FCCC1B6A0731DC87FE32669A5D154D85C47AB0E789623B140B8E919467819C9459A36E272170BFBC0A1928663F7AB527E4822069ABA7A332184B7ED5337EC9CB9DBFE2A15894D12FF68A1D61A8015AB36013C795BBF93699AA178428380E62C1";

//cd	S8 *charbuf_psk_1 = "B2C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
//	S8 *charbuf_psk_2 = "96EAFBAC26A0F3FD0BC31D10FD780CFEBE6DB81B44828F310A301CA1DEC2F25A";
//	S8 *charbuf_pubkey = "05356B1EAF98372C581FF73F41440A253B4F0BBAEB677020DB6C368DA9E3E92970E5E8559DE5A012F6FD0352F989568A4124B32298D8E3C7C13188D02610B22A";
//
//	S8 *charbuf_multpk = "D9BCB02D642185285E960E64B9BCF6DEFD90A12FB5879CDF711FBA09E4BD05A23E9185943985068FF70A8B21BEB76E8B3F073D2D5DDA5D1F70B1882F32636A80DA348DB00D8F1BF30A13F56E5F655CAB3E6DDEB20FC86B04F36577302962CA4C48C632690C68404C92350844C0A4963D822BB959CA8211AEECED31D710454A03";
//	S8 *charbuf_multsk = "D9BCB02D642185285E960E64B9BCF6DEFD90A12FB5879CDF711FBA09E4BD05A23E9185943985068FF70A8B21BEB76E8B3F073D2D5DDA5D1F70B1882F32636A7F020014D9E52E0BCB8A640B520894AFC969E7E8B9C230A11E998F33EB016F3F3DDE5DD973CF4AC34318F9D05AFD1A4A5B31C20D1B5FBAB4AD021B962EB9481610894B5AE2F6F4C12A86623C1AC5C97B0A46CED9B49541119D491E945284ABF36372D238BE63EAAACBACCFAE5B06CE2399F8AFA8E7178CB40D6A211A675EA2960E4C3443C9F40B66257310E3C273088F45202D57441D98D452AB853CF36367BDE3E621D4DB962A31706D2EDB0AB6A29D6D44D2460B59467C3F5223A1A9D020C353D9BCB02D642185285E960E64B9BCF6DEFD90A12FB5879CDF711FBA09E4BD05A23E9185943985068FF70A8B21BEB76E8B3F073D2D5DDA5D1F70B1882F32636A80DA348DB00D8F1BF30A13F56E5F655CAB3E6DDEB20FC86B04F36577302962CA4C48C632690C68404C92350844C0A4963D822BB959CA8211AEECED31D710454A03";



	//k1 + k2 = 882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
	//p1 + p2 = 31A10DD1B9CCD87518B9A4F3281269EA849EAC929FDCEC47FDFD3B786E934600
	//alpha   = 763B1F20467E6214B62FD5E729CA1BB827471E2A133C9D2B7BD3E0790598CA55
	//beta    = 
	S8 *charbuf_P1_k1 = "C6753F4B61D6177FD7E770E6BF5716146A54300114D0DF8C32DCF1FED0F9E31A";
	S8 *charbuf_P1_p1 = "B05A4355B5811D6E9FB17E5BB61F4E5BD8E39B20F9685CE25A62B09F219650A1";
	S8 *charbuf_P2_k2 = "C1B3C6A5C0A9BEA1240B3B0B52EDDAA4D42B89202B7B9C6E712F8C46574CFBDB";
	S8 *charbuf_P2_p2 = "8146CA7C044BBB067908269771F31B8D6669EE5855BD2FA1636CE9661D3336A0";
	S8 *charbuf_P1_R1 = "13C75CEF43AA92C411DC565E23E8D8D170D264C227A4B21D624B2E8677C75742A0C20A9C8465BE7A8B91900D995775D5E0B33A6D1BDB3C677A473713FDB14A05";
	S8 *charbuf_P2_R2 = "BE35E322089CEB5290D99932C78F392E893EDAA0BCB38B7F211BC3D1212E2B1EC908130F3693047298399F6FE6D112316200DDC9DEF0F03D26D037A2E6FDABB7";

	S8 *charbuf_P1_ZK = "3DE71EEA3561F13C745C09F68E0AEB966F54A2EACEE2A421EF86BEA47B39BDCB6972BC5BE3FCE35E189746645B19DDF90871530187ED0808C34787500402881D";
	S8 *charbuf_P2_ZK = "4780442B390730DC6FDF054530EEC7B8427A962E9A1E17C70ED103703C5EB917E8DB55C6F269908CE2A828D93A27B644C8ADBDFC71919CA2557AC2B428693491";

	S8 *charbuf_P1_v1 = "A46031EEEF97E74FAFAFA236FDFDAF13B98BFFFDC8C26821C819D8F80CE5A72C";//零知识证明用的32B随机数
	S8 *charbuf_P1_v2 = "8146CA7C044BBB067908269771F31B8D6669EE5855BD2FA1636CE9661D3336A0A0087EC5479F5B9ABC273BC28CAAD126D8BDC17986C02F41D27F7A8F10F921AE348C5DE9D51EE3287F7A8D2A1B98D80999142FC9F930DB136594C566080B1C8570E97C82B3DC3397AF99B82922722725E8CA2F8C0ABEFE1397A385608AC5A50EB6027EC92447AF584D4A3E269520AD37D2036D4C92D2B0AD749A196A1F153AE7B6F80C7C140C857D7FBBBCF10C77AECBC8D8CDB1CB923036CDA6E5D3CE2EF39A12E730E9371C29D7FF9F98DF5DBD282D8BC07A703C1DA45422363DEF031AC38780FE88737AAFC876863B52683F06E32BDD9D49CCC4E7B19CF76C560BD2DFF6EDCE9348080082B17080863E2A198AF0360DC7B267C7AE7C1FADE336FA57B57C0C5618A7FB647EFA8648D311161BDAD927C94E8A4D06694C26CF75D763B9514C5C8DC65B18200C88023B377F1D8784F58EA0AAA884A79CA834BD976E037D103A14C137D41AF74C95B420514090D45EF824E15267C46C4EC3A32E4FFA22978B7E104738880A8694FE028F83219B89EA237EB667C4FD3DE269268B1F3CEDBCE5CC471F3B077C0E892F1A8F2F1D6AD99FABB344BE84329A677311F3AEAAD8E7F76901E1F1A3A066FE6004558D7CA3F57F0970BBBE815FE6F6F410E7B674EBABE45FC0D85DDD8135D78044B40CD8A7F9A42BCB794D1423BF86BAF144853E7A11969F50";//零知识证明用的随机数
	S8 *charbuf_P2_v1 = "290204E1E32B21132798F73B806314FB0A50F9BD77264F9FAF61700F95886B1E";//零知识证明用的随机数
	S8 *charbuf_P2_v2 = "EBA1FA088C19AFA1F6D93447BA4DD396389AA9F238148C81C1FFDB6BB4014E623D34F21DD865C7314392685D0FB6A60C31727952ACECC785A0DE08E73DF5E054FA72E85C7C9B2606FC167A10735A9F1E155B66A7F31449D6624EF9D4354CFD3B2B5C70E34AC8FBC209B818B047DC3A7D474A4A519381074D71E6BAC6D7E3E57AB548E87042B82448762F956590B7D785D5AA095D18E221E8972FBEEFA503B7CBDD2818536D65C22E2C3E817AADF489D78B67A743DF75AA4A698E0FB951BFB858DAF07B1EE0CC5AF953893DDC3307F3CDC3CFDE5CB14F47B6D304A56691E7F282CFBECEA98D23E59660EFA5A877868850300F8967CB7BB9F18BC2F24A5E953489487354CC4BFA812017AC78489C50F7D840F9112BDD5264A973999D41B2463C0AC98E98157F8688CC73D76ABEB5B38DDCDD11FCEC4CD033215826F5BBEA1854E8DFA53E5BB8F04AAF77042F9B810F4AB5984327DD21D943F1DE4C20F1C42B20356AEEA7F7C84D29B8396F994830BA72FD67843BFC2069D604362E54DE35E179D87791593821378C5152830024ACC14A0ACF7DC1A676CC4500CA7B5B48BEA92FABA8646A636D4A11642F7DD8EF89FDBFEAE760279140C45E05A1F2D0CA45165D3F07417D6134D620B4F9BC3879426426E3D3BACF2C87FC434449A46450F1D85E6F7BAC91F46ECE14F22559B33FC7B809DC1AA2FD56C65091A5B0E0B5A2FCFC81694A76A2B70E12E51D51B6E71C243621BBAEA189C0E035A6A69B258D379A955D54AB61592F792D829DD30F4FF7EAFDCD487C9B3607153E0346923B8A22F0171CF8D8D122867AA9EBB6602B57A31B3016C4CD3347CFF4784C899A8588FFF261D9D6B5B5C0CA61858F48284E3B7021A236B87D82C59685226E4525B52F974D98BAFC";//零知识证明用的随机数

	U8 pb_P1_SK[32];
	U8 pb_P2_SK[32];
	U8 pbPubKey[64];

	U8 pbMultSK[384];
	U8 pbMultPK[128];

	U8 pb_Msg_e[32];
	U8 pb_Sign[64];
	U8 *pb_Sig_r;
	U8 *pb_Sig_s;

	U8 pb_P1_k1[32];
	U8 pb_P1_p1[32];
	U8 pb_P2_k2[32];
	U8 pb_P2_p2[32];
	U8 bytebuf_P1_R1[64];
	U8 bytebuf_P2_R2[64];

	U8 pb_P1_ZK[64];
	U8 pb_P2_ZK[64];

	U8 pb_P1_A1[32];
	U8 pb_P1_B1[32];
	U8 pb_P2_A2[32];
	U8 pb_P2_B2[32];

	U8 pbTmpKey[64];
	//U8 pbTmpZkp[64];
	S32 charlen = 0;
	S32 bytelen = 0;
	S32 ret = 0;
	int flag = 0;

	


	U8 bytebuf_P1_v1[32];
	U8 bytebuf_P1_v2[128 * 4];
	U8 bytebuf_P2_v1[32];
	U8 bytebuf_P2_v2[160 * 4];

	U8 pb_By_P1[448];
	U8 pb_To_P2[1280];
	U8 pb_To_P1[1024];

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	//得到标准数据
	ret = CharToByte(charbuf_psk_1, 64, pb_P1_SK, &bytelen);
	ret = CharToByte(charbuf_psk_2, 64, pb_P2_SK, &bytelen);
	ret = CharToByte(charbuf_pubkey, 128, pbPubKey, &bytelen);

	ret = CharToByte(charbuf_multpk, 128 * 2, pbMultPK, &bytelen);
	ret = CharToByte(charbuf_multsk, 384 * 2, pbMultSK, &bytelen);

	ret = CharToByte(charbuf_hash, 64, pb_Msg_e, &bytelen);
	ret = CharToByte(charbuf_sign, 128, pb_Sign, &bytelen);
	pb_Sig_r = pb_Sign;
	pb_Sig_s = pb_Sign + 32;

	ret = CharToByte(charbuf_P1_k1, 64, pb_P1_k1, &bytelen);
	ret = CharToByte(charbuf_P1_p1, 64, pb_P1_p1, &bytelen);
	ret = CharToByte(charbuf_P1_v1, 64, bytebuf_P1_v1, &bytelen);
	ret = CharToByte(charbuf_P1_v2, 128 * 8, bytebuf_P1_v2, &bytelen);
	ret = CharToByte(charbuf_P1_R1, 128, bytebuf_P1_R1, &bytelen);
	ret = CharToByte(charbuf_P1_ZK, 128, pb_P1_ZK, &bytelen);

	ret = CharToByte(charbuf_P2_k2, 64, pb_P2_k2, &bytelen);
	ret = CharToByte(charbuf_P2_p2, 64, pb_P2_p2, &bytelen);
	ret = CharToByte(charbuf_P2_v1, 64, bytebuf_P2_v1, &bytelen);
	ret = CharToByte(charbuf_P2_v2, 160 * 8, bytebuf_P2_v2, &bytelen);
	ret = CharToByte(charbuf_P2_R2, 128, bytebuf_P2_R2, &bytelen);
	ret = CharToByte(charbuf_P2_ZK, 128, pb_P2_ZK, &bytelen);

	/*---------------------------------------------------------------------------------------------------------------------*/

	//P1 Proof R1
	ret = ECDSA_DiCo_Sign_Part1_SetR(pbTmpKey, pb_P1_ZK, &m_SECP256K1_Sys_Para, pb_P1_k1, bytebuf_P1_v1);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, bytebuf_P1_R1, 64) != 0)/* ||
		(memcmp(pbTmpZkp, pb_P1_ZK, 64) != 0)*/)
	{
		flag++;
	}

	//P2 Proof R2 and Verify R1
	ret = ECDSA_DiCo_Sign_Part1_SetR(pbTmpKey, pb_P2_ZK, &m_SECP256K1_Sys_Para, pb_P2_k2, bytebuf_P2_v1);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, bytebuf_P2_R2, 64) != 0)/* ||
		(memcmp(pbTmpZkp, pb_P2_ZK, 64) != 0)*/)
	{
		flag++;
	}
	ret = ECDSA_DiCo_Sign_Part1_GetR(pbTmpKey, &m_SECP256K1_Sys_Para, pb_P2_k2, bytebuf_P2_R2, bytebuf_P1_R1, pb_P1_ZK);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, pb_Sig_r, 32) != 0))
	{
		flag++;
	}

	//P1 Verify
	ret = ECDSA_DiCo_Sign_Part1_GetR(pbTmpKey, &m_SECP256K1_Sys_Para, pb_P1_k1, bytebuf_P1_R1, bytebuf_P2_R2, pb_P2_ZK);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, pb_Sig_r, 32) != 0))
	{
		flag++;
	}


	/*---------------------------------------------------------------------------------------------------------------------*/

	//P1 Send
	ret = ECDSA_DiCo_Sign_Part2_Send(pb_By_P1, pb_To_P2, &m_SECP256K1_Sys_Para,
		pb_Msg_e, pb_Sig_r, pb_P1_SK, pb_P1_k1, pb_P1_p1, pbMultPK, bytebuf_P1_v2);
	if ((ret != 1))
	{
		flag++;
	}

	//P2 Mult
	ret = ECDSA_DiCo_Sign_Part2_Mult(pb_To_P1, pb_P2_A2, pb_P2_B2, &m_SECP256K1_Sys_Para,
		pb_Msg_e, pb_Sig_r, pb_P2_SK, pb_P2_k2, pb_P2_p2, pbMultPK, pb_To_P2, bytebuf_P2_v2);
	if ((ret != 1))
	{
		flag++;
	}

	//P1 Recv
	ret = ECDSA_DiCo_Sign_Part2_Recv(pb_P1_A1, pb_P1_B1, &m_SECP256K1_Sys_Para,
		pbMultSK, pb_By_P1, pb_To_P1);
	if ((ret != 1))
	{
		flag++;
	}

	//P1 or P2 get s
	ret = ECDSA_DiCo_Sign_Part2_GetS(pbTmpKey, &m_SECP256K1_Sys_Para,
		pb_P1_A1, pb_P1_B1, pb_P2_A2, pb_P2_B2);
	if ((ret != 1) ||
		(memcmp(pbTmpKey, pb_Sig_s, 32) != 0))
	{
		flag++;
	}

	/*---------------------------------------------------------------------------------------------------------------------*/
	int i;
	printf("pb_Msg_e：");
	for (i = 0; i < 32; i++)
	{
		printf("%02X", pb_Msg_e[i]);
	}
	printf("\n");

	printf("pbPubKey：");
	for (i = 0; i < 64; i++)
	{
		printf("%02X", pbPubKey[i]);
	}
	printf("\n");

	printf("pb_Sign：");
	for (i = 0; i < 64; i++)
	{
		printf("%02X", pb_Sign[i]);
	}
	printf("\n");


	ret = ECDSA_DiCo_Verify(&m_SECP256K1_Sys_Para, pb_Msg_e, pbPubKey, pb_Sign);
	if ((ret != 1))
	{
		flag++;
	}


	if (flag)
	{
		printf("The testing of ECDSA_DiCo_Sign_Test is wrong!\n");
	}
	else
	{
		printf("The testing of ECDSA_DiCo_Sign_Test is right!\n");
	}
}


void ECDSA_DiCo_Sign_Verify_Random_Test()
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };

	U8 pbP1_Rnd[1000];
	U8 pbP2_Rnd[1000];
	U8 *pb_P1_sk, *pb_P1_k1, *pb_P1_p1, *pb_P1_v0, *pb_P1_v1, *pb_P1_v2;
	U8 *pb_P2_sk, *pb_P2_k2, *pb_P2_p2, *pb_P2_v0, *pb_P2_v1, *pb_P2_v2;
	U8 pb_P1_pk[64], pb_P1_ZK[64], pb_P1_R1[64], pb_P1_A1[32], pb_P1_B1[32];
	U8 pb_P2_pk[64], pb_P2_ZK[64], pb_P2_R2[64], pb_P2_A2[32], pb_P2_B2[32];
	U8 pbPubKey[64], pbTmpKey[64];
	U8 pbSign[64], *pb_Sig_r, *pb_Sig_s;
	U8 pb_Msg_e[32];
	U8 pbMultSK[384], pbMultPK[128];

	U8 pb_By_P1[64];
	U8 pb_To_P2[1024];
	U8 pb_To_P1[1024];

	S32 charlen = 0;
	S32 bytelen = 0;
	S32 ret = 0;
	int flag = 0;

	int i, j;

	//初始化系统参数
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);

	pb_Sig_r = pbSign;
	pb_Sig_s = pbSign + 32;

	for (i = 0; i < 100; i++)
	{
		cela_rand(pb_Msg_e, 32);
		cela_rand(pbP1_Rnd, 1000);
		cela_rand(pbP2_Rnd, 1000);

		//for (j = 0; j < 32; j++)
		//{
		//	pb_Msg_e[j] = (U8)rand();
		//}

		//for (j = 0; j < 1000; j++)
		//{
		//	pbP1_Rnd[j] = (U8)rand();
		//	pbP2_Rnd[j] = (U8)rand();
		//}

		pb_P1_sk = pbP1_Rnd;
		pb_P1_k1 = pbP1_Rnd + 32;
		pb_P1_p1 = pbP1_Rnd + 64;
		pb_P1_v0 = pbP1_Rnd + 96;
		pb_P1_v1 = pbP1_Rnd + 128;
		pb_P1_v2 = pbP1_Rnd + 160;

		pb_P2_sk = pbP2_Rnd;
		pb_P2_k2 = pbP2_Rnd + 32;
		pb_P2_p2 = pbP2_Rnd + 64;
		pb_P2_v0 = pbP2_Rnd + 96;
		pb_P2_v1 = pbP2_Rnd + 128;
		pb_P2_v2 = pbP2_Rnd + 160;


		/*---------------------------------------------------------------------------------------------------------------------*/

		//P1 Proof
		ret = ECDSA_DiCo_KeyGen_P1_Send(pbMultSK, pbMultPK, pb_P1_pk, pb_P1_ZK, &m_SECP256K1_Sys_Para, pb_P1_sk, pb_P1_v0);
		if ((ret != 1))
		{
			flag++;
		}

		//P2 Proof and Verify
		ret = ECDSA_DiCo_KeyGen_P2_Done(pbPubKey, pb_P2_pk, pb_P2_ZK, &m_SECP256K1_Sys_Para, pbMultPK, pb_P2_sk, pb_P1_pk, pb_P1_ZK, pb_P2_v0);
		if ((ret != 1))
		{
			flag++;
		}

		//P1 Verify
		ret = ECDSA_DiCo_KeyGen_P1_Recv(pbTmpKey, &m_SECP256K1_Sys_Para, pbMultPK, pb_P1_sk, pb_P1_pk, pb_P2_pk, pb_P2_ZK);
		if ((ret != 1) ||
			(memcmp(pbTmpKey, pbPubKey, 64) != 0))
		{
			flag++;
		}
		

		/*---------------------------------------------------------------------------------------------------------------------*/

		//P1 Proof R1
		ret = ECDSA_DiCo_Sign_Part1_SetR(pb_P1_R1, pb_P1_ZK, &m_SECP256K1_Sys_Para, pb_P1_k1, pb_P1_v1);
		if ((ret != 1))
		{
			flag++;
		}

		//P2 Proof R2 and Verify R1
		ret = ECDSA_DiCo_Sign_Part1_SetR(pb_P2_R2, pb_P2_ZK, &m_SECP256K1_Sys_Para, pb_P2_k2, pb_P2_v1);
		if ((ret != 1))
		{
			flag++;
		}
		ret = ECDSA_DiCo_Sign_Part1_GetR(pb_Sig_r, &m_SECP256K1_Sys_Para, pb_P2_k2, pb_P2_R2, pb_P1_R1, pb_P1_ZK);
		if ((ret != 1))
		{
			flag++;
		}

		//P1 Verify
		ret = ECDSA_DiCo_Sign_Part1_GetR(pbTmpKey, &m_SECP256K1_Sys_Para, pb_P1_k1, pb_P1_R1, pb_P2_R2, pb_P2_ZK);
		if ((ret != 1) ||
			(memcmp(pbTmpKey, pb_Sig_r, 32) != 0))
		{
			flag++;
		}

		/*---------------------------------------------------------------------------------------------------------------------*/

		//P1 Send
		ret = ECDSA_DiCo_Sign_Part2_Send(pb_By_P1, pb_To_P2, &m_SECP256K1_Sys_Para,
			pb_Msg_e, pb_Sig_r, pb_P1_sk, pb_P1_k1, pb_P1_p1, pbMultPK, pb_P1_v2);
		if ((ret != 1))
		{
			flag++;
		}

		//P2 Mult
		ret = ECDSA_DiCo_Sign_Part2_Mult(pb_To_P1, pb_P2_A2, pb_P2_B2, &m_SECP256K1_Sys_Para,
			pb_Msg_e, pb_Sig_r, pb_P2_sk, pb_P2_k2, pb_P2_p2, pbMultPK, pb_To_P2, pb_P2_v2);
		if ((ret != 1))
		{
			flag++;
		}

		//P1 Recv
		ret = ECDSA_DiCo_Sign_Part2_Recv(pb_P1_A1, pb_P1_B1, &m_SECP256K1_Sys_Para,
			pbMultSK, pb_By_P1, pb_To_P1);
		if ((ret != 1))
		{
			flag++;
		}

		//P1 or P2 get s
		ret = ECDSA_DiCo_Sign_Part2_GetS(pb_Sig_s, &m_SECP256K1_Sys_Para,
			pb_P1_A1, pb_P1_B1, pb_P2_A2, pb_P2_B2);
		if ((ret != 1))
		{
			flag++;
		}

		/*---------------------------------------------------------------------------------------------------------------------*/
		//Verify (r,s)
		ret = ECDSA_DiCo_Verify(&m_SECP256K1_Sys_Para, pb_Msg_e, pbPubKey, pbSign);
		if ((ret != 1))
		{
			flag++;
		}

		pbSign[0]++;
		ret = ECDSA_DiCo_Verify(&m_SECP256K1_Sys_Para, pb_Msg_e, pbPubKey, pbSign);
		if ((ret == 1))
		{
			flag++;
		}
		pbSign[0]--;

		pbSign[56]++;
		ret = ECDSA_DiCo_Verify(&m_SECP256K1_Sys_Para, pb_Msg_e, pbPubKey, pbSign);
		if ((ret == 1))
		{
			flag++;
		}
		pbSign[56]--;

		if (flag)
		{
			printf("[Round-%04d],The testing of ECDSA_DiCo_Sign_Verify_Random_Test is wrong!\n", i);
			printf("---------------------------------------------------------------------\n");
			printf("Msg_e:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_Msg_e[j]);
			}
			printf("\n");
			printf("PubKey:\n");
			for (j = 0; j < 64; j++)
			{
				printf("%02X", pbPubKey[j]);
			}
			printf("\n");
			printf("P1-x1:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P1_sk[j]);
			}
			printf("\n");
			printf("P1-k1:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P1_k1[j]);
			}
			printf("\n");
			printf("P1-p1:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P1_p1[j]);
			}
			printf("\n");
			printf("P1-alpha:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P1_A1[j]);
			}
			printf("\n");
			printf("P1-beta:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P1_B1[j]);
			}
			printf("\n");

			printf("P2-x2:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P2_sk[j]);
			}
			printf("\n");
			printf("P2-k2:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P2_k2[j]);
			}
			printf("\n");
			printf("P2-p2:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P2_p2[j]);
			}
			printf("\n");
			printf("P2-alpha:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P2_A2[j]);
			}
			printf("\n");
			printf("P2-beta:\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_P2_B2[j]);
			}
			printf("\n");
			printf("(r,s):\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_Sig_r[j]);
			}
			printf("\n");
			for (j = 0; j < 32; j++)
			{
				printf("%02X", pb_Sig_s[j]);
			}
			printf("\n");
			printf("---------------------------------------------------------------------\n");
		}
		else
		{
			printf("[Round-%04d],The testing of ECDSA_DiCo_Sign_Verify_Random_Test is right!\n", i);
		}
	}


}
