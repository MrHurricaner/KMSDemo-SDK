#include "com_juzix_kms_NativeECDSA.h"
#include "secp256k1_curve.h"

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1KeyGen_1P1_1Send
  (JNIEnv *env, jclass object, jbyteArray pbP1_SK, jbyteArray pbRand)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
    U8 pbP1_SK_c[32];
	U8 pbRand_c[32];
	U8 pbMultSK_c[384];
	U8 pbMultPK_c[128];
	U8 pbP1_PK_c[64];
	U8 pbP1_ZK_c[64];
    
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
    (*env)->GetByteArrayRegion(env, pbP1_SK, 0, 32, (jbyte*)pbP1_SK_c);
	(*env)->GetByteArrayRegion(env, pbRand, 0, 32, (jbyte*)pbRand_c);
	ret = ECDSA_DiCo_KeyGen_P1_Send(pbMultSK_c, pbMultPK_c, pbP1_PK_c, pbP1_ZK_c, &m_SECP256K1_Sys_Para, pbP1_SK_c, pbRand_c);

	jbyteArray pbMultSK = (*env)->NewByteArray(env, 384);
	(*env)->SetByteArrayRegion(env, pbMultSK, 0, 384, pbMultSK_c);
	jbyteArray pbMultPK = (*env)->NewByteArray(env, 128);
	(*env)->SetByteArrayRegion(env, pbMultPK, 0, 128, pbMultPK_c);
	jbyteArray pbP1_PK = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbP1_PK, 0, 64, pbP1_PK_c);
	jbyteArray pbP1_ZK = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbP1_ZK, 0, 64, pbP1_ZK_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnKeyGenSend");
	jfieldID pbMultSK_f = (*env)->GetFieldID(env, jcs, "pbMultSK", "[B");
	jfieldID pbMultPK_f = (*env)->GetFieldID(env, jcs, "pbMultPK", "[B");
	jfieldID pbP1_PK_f = (*env)->GetFieldID(env, jcs, "pbP1_PK", "[B");
	jfieldID pbP1_ZK_f = (*env)->GetFieldID(env, jcs, "pbP1_ZK", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbMultSK_f, pbMultSK);
	(*env)->SetObjectField(env, resObj, pbMultPK_f, pbMultPK);
	(*env)->SetObjectField(env, resObj, pbP1_PK_f, pbP1_PK);
	(*env)->SetObjectField(env, resObj, pbP1_ZK_f, pbP1_ZK);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1KeyGen_1P2_1Done
  (JNIEnv *env, jclass object, jbyteArray pbMultPK, jbyteArray pbP2_SK, jbyteArray pbP1_PK, jbyteArray pbP1_ZK, jbyteArray pbRand)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
    U8 pbMultPK_c[128];
	U8 pbP2_SK_c[32];
	U8 pbP1_PK_c[64];
	U8 pbP1_ZK_c[64];
	U8 pbRand_c[32];
	U8 pbPubKey_c[64];
	U8 pbP2_PK_c[64];
	U8 pbP2_ZK_c[64];
    
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
    (*env)->GetByteArrayRegion(env, pbMultPK, 0, 128, (jbyte*)pbMultPK_c);
	(*env)->GetByteArrayRegion(env, pbP2_SK, 0, 32, (jbyte*)pbP2_SK_c);
	(*env)->GetByteArrayRegion(env, pbP1_PK, 0, 64, (jbyte*)pbP1_PK_c);
	(*env)->GetByteArrayRegion(env, pbP1_ZK, 0, 64, (jbyte*)pbP1_ZK_c);
	(*env)->GetByteArrayRegion(env, pbRand, 0, 32, (jbyte*)pbRand_c);
	ret = ECDSA_DiCo_KeyGen_P2_Done(pbPubKey_c, pbP2_PK_c, pbP2_ZK_c, &m_SECP256K1_Sys_Para, pbMultPK_c, pbP2_SK_c, pbP1_PK_c, pbP1_ZK_c, pbRand_c);

	jbyteArray pbPubKey = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbPubKey, 0, 64, pbPubKey_c);
	jbyteArray pbP2_PK = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbP2_PK, 0, 64, pbP2_PK_c);
	jbyteArray pbP2_ZK = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbP2_ZK, 0, 64, pbP2_ZK_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnKeyGenDone");
	jfieldID pbPubKey_f = (*env)->GetFieldID(env, jcs, "pbPubKey", "[B");
	jfieldID pbP2_PK_f = (*env)->GetFieldID(env, jcs, "pbP2_PK", "[B");
	jfieldID pbP2_ZK_f = (*env)->GetFieldID(env, jcs, "pbP2_ZK", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbPubKey_f, pbPubKey);
	(*env)->SetObjectField(env, resObj, pbP2_PK_f, pbP2_PK);
	(*env)->SetObjectField(env, resObj, pbP2_ZK_f, pbP2_ZK);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1KeyGen_1P1_1Recv
  (JNIEnv *env, jclass object, jbyteArray pbMultPK, jbyteArray pbP1_SK, jbyteArray pbP1_PK, jbyteArray pbP2_PK, jbyteArray pbP2_ZK)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
    U8 pbMultPK_c[128];
	U8 pbP1_SK_c[32];
	U8 pbP1_PK_c[64];
	U8 pbP2_PK_c[64];
	U8 pbP2_ZK_c[64];
	U8 pbPubKey_c[64];
    
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
    (*env)->GetByteArrayRegion(env, pbMultPK, 0, 128, (jbyte*)pbMultPK_c);
	(*env)->GetByteArrayRegion(env, pbP1_SK, 0, 32, (jbyte*)pbP1_SK_c);
	(*env)->GetByteArrayRegion(env, pbP1_PK, 0, 64, (jbyte*)pbP1_PK_c);
	(*env)->GetByteArrayRegion(env, pbP2_PK, 0, 64, (jbyte*)pbP2_PK_c);
	(*env)->GetByteArrayRegion(env, pbP2_ZK, 0, 64, (jbyte*)pbP2_ZK_c);
	ret = ECDSA_DiCo_KeyGen_P1_Recv(pbPubKey_c, &m_SECP256K1_Sys_Para, pbMultPK_c, pbP1_SK_c, pbP1_PK_c, pbP2_PK_c, pbP2_ZK_c);

	jbyteArray pbPubKey = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbPubKey, 0, 64, pbPubKey_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnKeyGenRecv");
	jfieldID pbPubKey_f = (*env)->GetFieldID(env, jcs, "pbPubKey", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbPubKey_f, pbPubKey);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part1_1SetR
  (JNIEnv *env, jclass object, jbyteArray pbBN_k1, jbyteArray pbRand) {
 	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
    U8 pbBN_k1_c[32];
	U8 pbRand_c[32];
	U8 pbEC_R1_c[64];
	U8 pbZK_P1_c[64];
    
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
    (*env)->GetByteArrayRegion(env, pbBN_k1, 0, 32, (jbyte*)pbBN_k1_c);	
	(*env)->GetByteArrayRegion(env, pbRand, 0, 32, (jbyte*)pbRand_c);
	ret = ECDSA_DiCo_Sign_Part1_SetR(pbEC_R1_c, pbZK_P1_c, &m_SECP256K1_Sys_Para, pbBN_k1_c, pbRand_c);

	jbyteArray pbEC_R1 = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbEC_R1, 0, 64, pbEC_R1_c);
	jbyteArray pbZK_P1 = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, pbZK_P1, 0, 64, pbZK_P1_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnSetR");
	jfieldID pbEC_R1_f = (*env)->GetFieldID(env, jcs, "pbEC_R1", "[B");
	jfieldID pbZK_P1_f = (*env)->GetFieldID(env, jcs, "pbZK_P1", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbEC_R1_f, pbEC_R1);
	(*env)->SetObjectField(env, resObj, pbZK_P1_f, pbZK_P1);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part1_1GetR
  (JNIEnv *env, jclass object, jbyteArray pbBN_k1, jbyteArray pbEC_R1, jbyteArray pbEC_R2, jbyteArray pbZK_P2)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbBN_k1_c[32];
	U8 pbEC_R1_c[64];
	U8 pbEC_R2_c[64];
	U8 pbZK_P2_c[64];
	U8 pbBN_r_c[32];

	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbBN_k1, 0, 32, (jbyte*)pbBN_k1_c);
	(*env)->GetByteArrayRegion(env, pbEC_R1, 0, 64, (jbyte*)pbEC_R1_c);
	(*env)->GetByteArrayRegion(env, pbEC_R2, 0, 64, (jbyte*)pbEC_R2_c);
	(*env)->GetByteArrayRegion(env, pbZK_P2, 0, 64, (jbyte*)pbZK_P2_c);
	ret = ECDSA_DiCo_Sign_Part1_GetR(pbBN_r_c, &m_SECP256K1_Sys_Para, pbBN_k1_c, pbEC_R1_c, pbEC_R2_c, pbZK_P2_c);

	jbyteArray pbBN_r = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_r, 0, 32, pbBN_r_c);
	
	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnGetR");
	jfieldID pbBN_r_f = (*env)->GetFieldID(env, jcs, "pbBN_r", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbBN_r_f, pbBN_r);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part2_1Send
  (JNIEnv *env, jclass object, jbyteArray pbBN_e, jbyteArray pbBN_r, jbyteArray pbBN_x1, jbyteArray pbBN_k1, jbyteArray pbBN_p1, jbyteArray pbMultPK, jbyteArray pbRand)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbBN_e_c[32];
	U8 pbBN_r_c[32];
	U8 pbBN_x1_c[32];
	U8 pbBN_k1_c[32];
	U8 pbBN_p1_c[32];
	U8 pbMultPK_c[128];
	U8 pbRand_c[512];
	U8 pbMP_ByP1_c[448];
	U8 pbMP_ToP2_c[1280];

	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbBN_e, 0, 32, (jbyte*)pbBN_e_c);
	(*env)->GetByteArrayRegion(env, pbBN_r, 0, 32, (jbyte*)pbBN_r_c);
	(*env)->GetByteArrayRegion(env, pbBN_x1, 0, 32, (jbyte*)pbBN_x1_c);
	(*env)->GetByteArrayRegion(env, pbBN_k1, 0, 32, (jbyte*)pbBN_k1_c);
	(*env)->GetByteArrayRegion(env, pbBN_p1, 0, 32, (jbyte*)pbBN_p1_c);
	(*env)->GetByteArrayRegion(env, pbMultPK, 0, 128, (jbyte*)pbMultPK_c);
	(*env)->GetByteArrayRegion(env, pbRand, 0, 512, (jbyte*)pbRand_c);

	ret = ECDSA_DiCo_Sign_Part2_Send(pbMP_ByP1_c, pbMP_ToP2_c, &m_SECP256K1_Sys_Para,
		pbBN_e_c, pbBN_r_c, pbBN_x1_c, pbBN_k1_c, pbBN_p1_c, pbMultPK_c, pbRand_c);

	jbyteArray pbMP_ByP1 = (*env)->NewByteArray(env, 448);
	(*env)->SetByteArrayRegion(env, pbMP_ByP1, 0, 448, pbMP_ByP1_c);
	jbyteArray pbMP_ToP2 = (*env)->NewByteArray(env, 1280);
	(*env)->SetByteArrayRegion(env, pbMP_ToP2, 0, 1280, pbMP_ToP2_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnSend");
	jobject resObj = (*env)->AllocObject(env, jcs);
	jfieldID pbMP_ByP1_f = (*env)->GetFieldID(env, jcs, "pbMP_ByP1", "[B");
	jfieldID pbMP_ToP2_f = (*env)->GetFieldID(env, jcs, "pbMP_ToP2", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	
	(*env)->SetObjectField(env, resObj, pbMP_ByP1_f, pbMP_ByP1);
	(*env)->SetObjectField(env, resObj, pbMP_ToP2_f, pbMP_ToP2);
	(*env)->SetIntField(env, resObj, success_f, 1);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part2_1Mult
  (JNIEnv *env, jclass object, jbyteArray pbBN_e, jbyteArray pbBN_r, jbyteArray pbBN_x2, jbyteArray pbBN_k2, jbyteArray pbBN_p2, jbyteArray pbMultPK, jbyteArray pbMP_ToP2, jbyteArray pbRand)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbBN_e_c[32];
	U8 pbBN_r_c[32];
	U8 pbBN_x2_c[32];
	U8 pbBN_k2_c[32];
	U8 pbBN_p2_c[32];
	U8 pbMultPK_c[128];
	U8 pbMP_ToP2_c[1280];
	U8 pbRand_c[640];
	U8 pbMP_ToP1_c[1024];
	U8 pbBN_alpha2_c[32];
	U8 pbBN_beta2_c[32];

	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbBN_e, 0, 32, (jbyte*)pbBN_e_c);
	(*env)->GetByteArrayRegion(env, pbBN_r, 0, 32, (jbyte*)pbBN_r_c);
	(*env)->GetByteArrayRegion(env, pbBN_x2, 0, 32, (jbyte*)pbBN_x2_c);
	(*env)->GetByteArrayRegion(env, pbBN_k2, 0, 32, (jbyte*)pbBN_k2_c);
	(*env)->GetByteArrayRegion(env, pbBN_p2, 0, 32, (jbyte*)pbBN_p2_c);
	(*env)->GetByteArrayRegion(env, pbMultPK, 0, 128, (jbyte*)pbMultPK_c);
	(*env)->GetByteArrayRegion(env, pbMP_ToP2, 0, 1280, (jbyte*)pbMP_ToP2_c);
	(*env)->GetByteArrayRegion(env, pbRand, 0, 640, (jbyte*)pbRand_c);
	ret = ECDSA_DiCo_Sign_Part2_Mult(pbMP_ToP1_c, pbBN_alpha2_c, pbBN_beta2_c, &m_SECP256K1_Sys_Para,
		pbBN_e_c, pbBN_r_c, pbBN_x2_c, pbBN_k2_c, pbBN_p2_c, pbMultPK_c, pbMP_ToP2_c, pbRand_c);

	jbyteArray pbMP_ToP1 = (*env)->NewByteArray(env, 1024);
	(*env)->SetByteArrayRegion(env, pbMP_ToP1, 0, 1024, pbMP_ToP1_c);
	jbyteArray pbBN_alpha2 = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_alpha2, 0, 32, pbBN_alpha2_c);
	jbyteArray pbBN_beta2 = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_beta2, 0, 32, pbBN_beta2_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnMult");
	jfieldID pbMP_ToP1_f = (*env)->GetFieldID(env, jcs, "pbMP_ToP1", "[B");
	jfieldID pbBN_alpha2_f = (*env)->GetFieldID(env, jcs, "pbBN_alpha2", "[B");
	jfieldID pbBN_beta2_f = (*env)->GetFieldID(env, jcs, "pbBN_beta2", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbMP_ToP1_f, pbMP_ToP1);
	(*env)->SetObjectField(env, resObj, pbBN_alpha2_f, pbBN_alpha2);
	(*env)->SetObjectField(env, resObj, pbBN_beta2_f, pbBN_beta2);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part2_1Recv
  (JNIEnv *env, jclass object, jbyteArray pbMultSK, jbyteArray pbMP_ByP1, jbyteArray pbMP_ToP1)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbMultSK_c[384];
	U8 pbMP_ByP1_c[448];
	U8 pbMP_ToP1_c[1024];
	U8 pbBN_alpha1_c[32];
	U8 pbBN_beta1_c[32];

	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbMultSK, 0, 384, (jbyte*)pbMultSK_c);
	(*env)->GetByteArrayRegion(env, pbMP_ByP1, 0, 448, (jbyte*)pbMP_ByP1_c);
	(*env)->GetByteArrayRegion(env, pbMP_ToP1, 0, 1024, (jbyte*)pbMP_ToP1_c);
	ret = ECDSA_DiCo_Sign_Part2_Recv(pbBN_alpha1_c, pbBN_beta1_c, &m_SECP256K1_Sys_Para,
		pbMultSK_c, pbMP_ByP1_c, pbMP_ToP1_c);

	jbyteArray pbBN_alpha1 = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_alpha1, 0, 32, pbBN_alpha1_c);
	jbyteArray pbBN_beta1 = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_beta1, 0, 32, pbBN_beta1_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnRecv");
	jfieldID pbBN_alpha1_f = (*env)->GetFieldID(env, jcs, "pbBN_alpha1", "[B");
	jfieldID pbBN_beta1_f = (*env)->GetFieldID(env, jcs, "pbBN_beta1", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbBN_alpha1_f, pbBN_alpha1);
	(*env)->SetObjectField(env, resObj, pbBN_beta1_f, pbBN_beta1);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Sign_1Part2_1GetS
  (JNIEnv *env, jclass object, jbyteArray pbBN_alpha1, jbyteArray pbBN_beta1, jbyteArray pbBN_alpha2, jbyteArray pbBN_beta2)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbBN_alpha1_c[32];
	U8 pbBN_beta1_c[32];
	U8 pbBN_alpha2_c[32];
	U8 pbBN_beta2_c[32];
	U8 pbBN_s_c[32];

	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbBN_alpha1, 0, 32, (jbyte*)pbBN_alpha1_c);
	(*env)->GetByteArrayRegion(env, pbBN_beta1, 0, 32, (jbyte*)pbBN_beta1_c);
	(*env)->GetByteArrayRegion(env, pbBN_alpha2, 0, 32, (jbyte*)pbBN_alpha2_c);
	(*env)->GetByteArrayRegion(env, pbBN_beta2, 0, 32, (jbyte*)pbBN_beta2_c);
	ret = ECDSA_DiCo_Sign_Part2_GetS(pbBN_s_c, &m_SECP256K1_Sys_Para,
		pbBN_alpha1_c, pbBN_beta1_c, pbBN_alpha2_c, pbBN_beta2_c);

	jbyteArray pbBN_s = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, pbBN_s, 0, 32, pbBN_s_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnGetS");
	jfieldID pbBN_s_f = (*env)->GetFieldID(env, jcs, "pbBN_s", "[B");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetObjectField(env, resObj, pbBN_s_f, pbBN_s);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}

JNIEXPORT jobject JNICALL Java_com_juzix_kms_NativeECDSA_ECDSA_1DiCo_1Verify
  (JNIEnv *env, jclass object, jbyteArray pbHash, jbyteArray pbPubKey, jbyteArray pbSign)
{
	SECP256K1_Sys_Para m_SECP256K1_Sys_Para = { 0 };
	S32 ret = 0;
	U8 pbHash_c[32];
	U8 pbPubKey_c[64];
	U8 pbSign_c[64];
	
	SECP256K1_Init_Sys_Para(&m_SECP256K1_Sys_Para, SECP256K1_SysPar, 8);
	(*env)->GetByteArrayRegion(env, pbHash, 0, 32, (jbyte*)pbHash_c);
	(*env)->GetByteArrayRegion(env, pbPubKey, 0, 64, (jbyte*)pbPubKey_c);
	(*env)->GetByteArrayRegion(env, pbSign, 0, 64, (jbyte*)pbSign_c);
	ret = ECDSA_DiCo_Verify(&m_SECP256K1_Sys_Para, pbHash_c, pbPubKey_c, pbSign_c);

	jclass jcs = (*env)->FindClass(env, "com/juzix/kms/NativeECDSA$ReturnVerify");
	jfieldID success_f = (*env)->GetFieldID(env, jcs, "success", "I");
	jobject resObj = (*env)->AllocObject(env, jcs);
	(*env)->SetIntField(env, resObj, success_f, ret);

	return resObj;
}
