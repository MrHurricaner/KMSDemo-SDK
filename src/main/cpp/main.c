#include <stdio.h>
#include <math.h>
#include <time.h>
#include "libs/bn_test.h"
#include "libs/secp256k1_fp_ecp_test.h"
#include "libs/ecdsa_test.h"
#include "libs/ecdsa_di_co_test.h"

void main()
{

//    srand( (unsigned)time( NULL ) );
//
    
    
//    int u_8 = sizeof(U8);
//    int u_16 = sizeof(U16);
//    int u_32 = sizeof(U32);
//    int u_64 = sizeof(U64);
//
//    printf("%d\n",u_8);
//    printf("%d\n",u_16);
//    printf("%d\n",u_32);
//    printf("%d\n",u_64);
//
//    printf("Testing for BN");
	BN_ModAdd_Test();
//	  BN_ModAdd_Test_cd();
//      BN_ModSub_Test_cd();
//      BN_Modkkk_Test_cd();

//    BN_ModMul_Mont_Test();
//    BN_GetInv_Mont_Test();
//    BN_GetR_Test();
//    printf("end Testing for BN");
//
//    //Testing for system initialization
//    //SECP256K1_Init_Sys_Para_Test();
//
//    //Testing for elliptic curve over F(q)
//    //SECP256K1_Fp_ECP_KP_Test();
//
//    //Testing for ECDSA
//    //ECDSA_KeyGen_Test();
//    //ECDSA_Sign_Test();
//    //ECDSA_Verify_Test();
//    //ECDSA_Sign_Verify_Random_Test();
//
//    //Testing for Disttibuted ECDSA

//    printf("Testing for Disttibuted ECDSA!\n");
//    ECDSA_DiCo_Multiplier_Test();
//    ECDSA_DiCo_KeyGen_Test();
//    ECDSA_DiCo_Sign_Test();
//    ECDSA_DiCo_Sign_Verify_Random_Test();
//    printf("Test is Over!\n");

////    system("pause");
}
