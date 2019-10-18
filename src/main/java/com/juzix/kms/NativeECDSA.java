package com.juzix.kms;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class NativeECDSA {

    static {
        System.loadLibrary("MpcNative");
    }

    public static boolean isLinux() {
        return System.getProperty("os.name").toLowerCase().indexOf("linux") >= 0;
    }

    private static boolean isWin() {
        return System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;
    }

    private static void initLibrary(String prefix, String suffix) throws Exception {
        String name = prefix + suffix;
        System.out.println("Library file name:" + name);
        System.out.println("Library file route:" + NativeECDSA.class.getClassLoader().getResource("libs/" + name));
        InputStream in = NativeECDSA.class.getClassLoader().getResource("libs/" + name).openStream();
        File dll = File.createTempFile(prefix, suffix);
        FileOutputStream out = new FileOutputStream(dll);
        int i;
        byte[] buf = new byte[1024];
        while ((i = in.read(buf)) != -1) {
            out.write(buf, 0, i);
        }
        in.close();
        out.close();
        dll.deleteOnExit();
        String libPath = dll.toString();
        System.load(libPath);
    }

    /**
     * ECDSA两方协同签名——密钥生成算法——第一步
     * S32 ECDSA_DiCo_KeyGen_P1_Send(U8 *pbMultSK, U8 *pbMultPK, U8 *pbP1_PK, U8 *pbP1_ZK, SECP256K1_Sys_Para * pSys_Para, U8 *pbP1_SK, U8 *pbRand);
     */
    public static native ReturnKeyGenSend ECDSA_DiCo_KeyGen_P1_Send(byte[] pbP1_SK, byte[] pbRand);

    /**
     * ECDSA两方协同签名——密钥生成算法——第二步
     * S32 ECDSA_DiCo_KeyGen_P2_Done(U8 *pbPubKey, U8 *pbP2_PK, U8 *pbP2_ZK, SECP256K1_Sys_Para * pSys_Para, U8 *pbMultPK, U8 *pbP2_SK, U8 *pbP1_PK, U8 *pbP1_ZK, U8 *pbRand);
     */
    public static native ReturnKeyGenDone ECDSA_DiCo_KeyGen_P2_Done(byte[] pbMultPK, byte[] pbP2_SK, byte[] pbP1_PK, byte[] pbP1_ZK, byte[] pbRand);

    /**
     * ECDSA两方协同签名——密钥生成算法——第三步
     * S32 ECDSA_DiCo_KeyGen_P1_Recv(U8 *pbPubKey, SECP256K1_Sys_Para * pSys_Para, U8 *pbMultPK, U8 *pbP1_SK, U8 *pbP1_PK, U8 *pbP2_PK, U8 *pbP2_ZK)
     */
    public static native ReturnKeyGenRecv ECDSA_DiCo_KeyGen_P1_Recv(byte[] pbMultPK, byte[] pbP1_SK, byte[] pbP1_PK, byte[] pbP2_PK, byte[] pbP2_ZK);


    /**
     * ECDSA两方协同签名——签名算法第一部分（设置随机数）
     * S32 ECDSA_DiCo_Sign_Part1_SetR(U8 *pbEC_R1, U8 *pbZK_P1, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_k1, U8 *pbRand);
     */
    public static native ReturnSetR ECDSA_DiCo_Sign_Part1_SetR(byte[] pbBN_k1, byte[] pbRand);


    /**
     * ECDSA两方协同签名——签名算法第一部分（获取部分签名r）
     * S32 ECDSA_DiCo_Sign_Part1_GetR(U8 *pbBN_r, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_k1, U8 *pbEC_R1, U8 *pbEC_R2, U8 *pbZK_P2);
     */
    public static native ReturnGetR ECDSA_DiCo_Sign_Part1_GetR(byte[] pbBN_k1, byte[] pbEC_R1, byte[] pbEC_R2, byte[] pbZK_P2);


    /**
     * ECDSA两方协同签名——签名算法第一部分（获取部分签名r）
     * S32 ECDSA_DiCo_Sign_Part2_Send(U8 *pbMP_ByP1, U8 *pbMP_ToP2, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_e, U8 *pbBN_r, U8 *pbBN_x1, U8 *pbBN_k1, U8 *pbBN_p1, U8 *pbMultPK,U8 *pbRand);
     */
    public static native ReturnSend ECDSA_DiCo_Sign_Part2_Send(byte[] pbBN_e, byte[] pbBN_r, byte[] pbBN_x1, byte[] pbBN_k1, byte[] pbBN_p1, byte[] pbMultPK, byte[] pbRand);


    /**
     * ECDSA两方协同签名——签名算法第二部分（乘法器运算）
     * S32 ECDSA_DiCo_Sign_Part2_Mult(U8 *pbMP_ToP1, U8 *pbBN_alpha2, U8 *pbBN_beta2, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_e, U8 *pbBN_r, U8 *pbBN_x2, U8 *pbBN_k2, U8 *pbBN_p2, U8 *pbMultPK, U8 *pbMP_ToP2, U8 *pbRand);
     */
    public static native ReturnMult ECDSA_DiCo_Sign_Part2_Mult(byte[] pbBN_e, byte[] pbBN_r, byte[] pbBN_x2, byte[] pbBN_k2, byte[] pbBN_p2, byte[] pbMultPK, byte[] pbMP_ToP2, byte[] pbRand);


    /**
     * ECDSA两方协同签名——签名算法第二部分（乘法器响应）
     * S32 ECDSA_DiCo_Sign_Part2_Recv(U8 *pbBN_alpha1, U8 *pbBN_beta1, SECP256K1_Sys_Para * pSys_Para, U8 *pbMultSK, U8 *pbMP_ByP1, U8 *pbMP_ToP1);
     */
    public static native ReturnRecv ECDSA_DiCo_Sign_Part2_Recv(byte[] pbMultSK, byte[] pbMP_ByP1, byte[] pbMP_ToP1);

    /**
     * ECDSA两方协同签名——签名算法——第六步
     * S32 ECDSA_DiCo_Sign_Part2_GetS(U8 *pbBN_s, SECP256K1_Sys_Para * pSys_Para, U8 *pbBN_alpha1, U8 *pbBN_beta1, U8 *pbBN_alpha2, U8 *pbBN_beta2);
     */
    public static native ReturnGetS ECDSA_DiCo_Sign_Part2_GetS(byte[] pbBN_alpha1, byte[] pbBN_beta1, byte[] pbBN_alpha2, byte[] pbBN_beta2);

    /**
     * ECDSA两方协同签名——验签算法
     * S32 ECDSA_DiCo_Verify(SECP256K1_Sys_Para * pSys_Para, U8 *pbHash, U8 *pbPubKey, U8 *pbSign);
     */
    public static native ReturnVerify ECDSA_DiCo_Verify(byte[] pbHash, byte[] pbPubKey, byte[] pbSign);


    public static class ReturnKeyGenRecv {

        private byte[] pbPubKey;
        private int success;

        public byte[] getPbPubKey() {
            return pbPubKey;
        }

        public void setPbPubKey(byte[] pbPubKey) {
            this.pbPubKey = pbPubKey;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


    public static class ReturnKeyGenDone {

        private byte[] pbPubKey;
        private byte[] pbP2_PK;
        private byte[] pbP2_ZK;
        private int success;

        public byte[] getPbPubKey() {
            return pbPubKey;
        }

        public void setPbPubKey(byte[] pbPubKey) {
            this.pbPubKey = pbPubKey;
        }

        public byte[] getPbP2_PK() {
            return pbP2_PK;
        }

        public void setPbP2_PK(byte[] pbP2_PK) {
            this.pbP2_PK = pbP2_PK;
        }

        public byte[] getPbP2_ZK() {
            return pbP2_ZK;
        }

        public void setPbP2_ZK(byte[] pbP2_ZK) {
            this.pbP2_ZK = pbP2_ZK;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


    public static class ReturnKeyGenSend {

        private byte[] pbMultSK;
        private byte[] pbMultPK;
        private byte[] pbP1_PK;
        private byte[] pbP1_ZK;
        private int success;

        public byte[] getPbMultSK() {
            return pbMultSK;
        }

        public void setPbMultSK(byte[] pbMultSK) {
            this.pbMultSK = pbMultSK;
        }

        public byte[] getPbMultPK() {
            return pbMultPK;
        }

        public void setPbMultPK(byte[] pbMultPK) {
            this.pbMultPK = pbMultPK;
        }

        public byte[] getPbP1_PK() {
            return pbP1_PK;
        }

        public void setPbP1_PK(byte[] pbP1_PK) {
            this.pbP1_PK = pbP1_PK;
        }

        public byte[] getPbP1_ZK() {
            return pbP1_ZK;
        }

        public void setPbP1_ZK(byte[] pbP1_ZK) {
            this.pbP1_ZK = pbP1_ZK;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }

    public static class ReturnSend {

        private byte[] pbMP_ByP1 = new byte[64];
        private byte[] pbMP_ToP2 = new byte[1024];
        private int success;

        public byte[] getPbMP_ByP1() {
            return pbMP_ByP1;
        }

        public void setPbMP_ByP1(byte[] pbMP_ByP1) {
            this.pbMP_ByP1 = pbMP_ByP1;
        }

        public byte[] getPbMP_ToP2() {
            return pbMP_ToP2;
        }

        public void setPbMP_ToP2(byte[] pbMP_ToP2) {
            this.pbMP_ToP2 = pbMP_ToP2;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


    public static class ReturnVerify {

        private int success;

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }

    public static class ReturnGetS {

        private byte[] pbBN_s;
        private int success;

        public byte[] getPbBN_s() {
            return pbBN_s;
        }

        public void setPbBN_s(byte[] pbBN_s) {
            this.pbBN_s = pbBN_s;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }

    public static class ReturnRecv {

        private byte[] pbBN_alpha1;
        private byte[] pbBN_beta1;
        private int success;

        public byte[] getPbBN_alpha1() {
            return pbBN_alpha1;
        }

        public void setPbBN_alpha1(byte[] pbBN_alpha1) {
            this.pbBN_alpha1 = pbBN_alpha1;
        }

        public byte[] getPbBN_beta1() {
            return pbBN_beta1;
        }

        public void setPbBN_beta1(byte[] pbBN_beta1) {
            this.pbBN_beta1 = pbBN_beta1;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


    public static class ReturnMult {

        private byte[] pbMP_ToP1;
        private byte[] pbBN_alpha2;
        private byte[] pbBN_beta2;
        private int success;

        public byte[] getPbMP_ToP1() {
            return pbMP_ToP1;
        }

        public void setPbMP_ToP1(byte[] pbMP_ToP1) {
            this.pbMP_ToP1 = pbMP_ToP1;
        }

        public byte[] getPbBN_alpha2() {
            return pbBN_alpha2;
        }

        public void setPbBN_alpha2(byte[] pbBN_alpha2) {
            this.pbBN_alpha2 = pbBN_alpha2;
        }

        public byte[] getPbBN_beta2() {
            return pbBN_beta2;
        }

        public void setPbBN_beta2(byte[] pbBN_beta2) {
            this.pbBN_beta2 = pbBN_beta2;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


    public static class ReturnGetR {

        private byte[] pbBN_r;
        private int success;

        public byte[] getPbBN_r() {
            return pbBN_r;
        }

        public void setPbBN_r(byte[] pbBN_r) {
            this.pbBN_r = pbBN_r;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }

    public static class ReturnSetR {

        private byte[] pbEC_R1;
        private byte[] pbZK_P1;
        private int success;

        public byte[] getPbEC_R1() {
            return pbEC_R1;
        }

        public void setPbEC_R1(byte[] pbEC_R1) {
            this.pbEC_R1 = pbEC_R1;
        }

        public byte[] getPbZK_P1() {
            return pbZK_P1;
        }

        public void setPbZK_P1(byte[] pbZK_P1) {
            this.pbZK_P1 = pbZK_P1;
        }

        public int getSuccess() {
            return success;
        }

        public void setSuccess(int success) {
            this.success = success;
        }
    }


}

