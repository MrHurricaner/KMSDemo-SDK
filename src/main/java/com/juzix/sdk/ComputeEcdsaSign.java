package com.juzix.sdk;

import java.util.HashMap;
import java.util.Map;

import com.juzix.kms.HexUtil;
import com.juzix.kms.NativeECDSA;
import com.juzix.kms.NativeECDSA.ReturnGetR;
import com.juzix.kms.NativeECDSA.ReturnGetS;
import com.juzix.kms.NativeECDSA.ReturnMult;
import com.juzix.kms.NativeECDSA.ReturnRecv;
import com.juzix.kms.NativeECDSA.ReturnSend;
import com.juzix.kms.NativeECDSA.ReturnSetR;
import com.juzix.kms.SecureRandomUtils;

public class ComputeEcdsaSign implements Compute {
	
	public final static String COMPUTE_KEY = "ECDSASign";
	
	public final static String PARTY_P1 = "P1";
	public final static String PARTY_P2 = "P2";

	public final static String PB_EC_R1 = "pbEC_R1";
	public final static String PB_ZK_P1 = "pbZK_P1";
	
	public final static String PB_BN_K1 = "pbBN_k1";
	public final static String PB_BN_K2 = "pbBN_k2";
	
	public final static String SIGN_R = "pbBN_r";
	public final static String SIGN_S = "pbBN_s";
	
	
	public final static String DATA_HASH = "pbBN_e";
	public final static String P1_SK = "pbBN_x1";
	public final static String P2_SK = "pbBN_x2";

	public final static String MULT_SK = "pbMultSK";	
	public final static String MULT_PK = "pbMultPK";
	
	public final static String PB_MP_To_P2 = "pbMP_ToP2";
	public final static String PB_MP_By_P1 = "pbMP_ByP1";
	
	public final static String PB_BN_ALPHA2 = "pbBN_alpha2";
	public final static String PB_BN_BETA2 = "pbBN_beta2";
	
	public final static String PB_BN_ALPHA1 = "pbBN_alpha1";
	public final static String PB_BN_BETA1 = "pbBN_beta1";
	
	public final static String PB_MP_To_P1 = "pbMP_ToP1";
	
	
	@Override
	public String getKey() {
		return COMPUTE_KEY;
	}

	@Override
	public String beginParty() {
		return PARTY_P1;
	}

	@Override
	public ComputeResult nextStep(int step, Session session, Map<String, Object> params, Map<String, Object> input) {
		switch (step) {
		case 1:
			return step1(session, params, input);
		case 2:
			return step2(session, params, input);
		case 3:
			return step3(session, params, input);
		case 4:
			return step4(session, params, input);
		case 5:
			return step5(session, params, input);
		case 6:
			return step6(session, params, input);
		default:
			return null;
		}
	}
	
	private ComputeResult step1( Session session, Map<String, Object> params, Map<String, Object> input) {
    	//输入的用户参数
		String pbBN_e_Hex = (String)input.get(DATA_HASH);
    	byte[] pbBN_e = HexUtil.hexToByteArray(pbBN_e_Hex);
		String pbBN_x1_Hex = (String)input.get(P1_SK);
    	byte[] pbBN_x1 = HexUtil.hexToByteArray(pbBN_x1_Hex);
		String pbMultPK_Hex = (String)input.get(MULT_PK);
    	byte[] pbMultPK = HexUtil.hexToByteArray(pbMultPK_Hex);
		String pbMultSK_Hex = (String)input.get(MULT_SK);
    	byte[] pbMultSK = HexUtil.hexToByteArray(pbMultSK_Hex);
		
    	//随机数数字
		byte[] pbBN_k1 = new byte[32];
		byte[] pbRand1 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbBN_k1);
    		SecureRandomUtils.secureRandom().nextBytes(pbRand1);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbBN_k1);
//			SecureRandom.getInstanceStrong().nextBytes(pbRand1);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
    	
    	//调用算法
    	ReturnSetR returnSetR = NativeECDSA.ECDSA_DiCo_Sign_Part1_SetR(pbBN_k1, pbRand1);
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(false);
		
		//需要传递的会话
		session.setAttribute(PB_BN_K1, pbBN_k1);
		session.setAttribute(PB_EC_R1, returnSetR.getPbEC_R1());
		session.setAttribute(DATA_HASH, pbBN_e);
		session.setAttribute(P1_SK, pbBN_x1);
		session.setAttribute(MULT_PK, pbMultPK);
		session.setAttribute(MULT_SK, pbMultSK);
				
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_EC_R1, HexUtil.getHexString(returnSetR.getPbEC_R1()));
		toMap.put(PB_ZK_P1, HexUtil.getHexString(returnSetR.getPbZK_P1()));
		computeResult.getToOthers().put(PARTY_P2, toMap);
		return computeResult;
	}
	
	private ComputeResult step2( Session session, Map<String, Object> params, Map<String, Object> input) {
    	//输入的用户参数
		String pbBN_e_Hex = (String)input.get(DATA_HASH);
    	byte[] pbBN_e = HexUtil.hexToByteArray(pbBN_e_Hex);
		String pbBN_x2_Hex = (String)input.get(P2_SK);
    	byte[] pbBN_x2 = HexUtil.hexToByteArray(pbBN_x2_Hex);
		String pbMultPK_Hex = (String)input.get(MULT_PK);
    	byte[] pbMultPK = HexUtil.hexToByteArray(pbMultPK_Hex);
		
    	//随机数数字
		byte[] pbBN_k2 = new byte[32];
		byte[] pbRand2 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbBN_k2);
    		SecureRandomUtils.secureRandom().nextBytes(pbRand2);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbBN_k2);
//			SecureRandom.getInstanceStrong().nextBytes(pbRand2);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
    	
		//输入的过程参数
		String pbEC_R1_Hex = (String)params.get(PB_EC_R1);
    	byte[] pbEC_R1 = HexUtil.hexToByteArray(pbEC_R1_Hex);
		String pbZK_P1_Hex = (String)params.get(PB_ZK_P1);
    	byte[] pbZK_P1 = HexUtil.hexToByteArray(pbZK_P1_Hex);
    	
    	//调用算法
    	ReturnSetR returnSetR = NativeECDSA.ECDSA_DiCo_Sign_Part1_SetR(pbBN_k2, pbRand2);
    	ReturnGetR returnGetR = NativeECDSA.ECDSA_DiCo_Sign_Part1_GetR(pbBN_k2, returnSetR.getPbEC_R1(), pbEC_R1, pbZK_P1);
        
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(false);
		
		//需要传递的会话
		session.setAttribute(PB_BN_K2, pbBN_k2);
		session.setAttribute(SIGN_R, returnGetR.getPbBN_r());
		session.setAttribute(DATA_HASH, pbBN_e);
		session.setAttribute(P2_SK, pbBN_x2);
		session.setAttribute(MULT_PK, pbMultPK);
		
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_EC_R1, HexUtil.getHexString(returnSetR.getPbEC_R1()));
		toMap.put(PB_ZK_P1, HexUtil.getHexString(returnSetR.getPbZK_P1()));
		computeResult.getToOthers().put(PARTY_P1, toMap);
		return computeResult;
	}
	
	private ComputeResult step3( Session session, Map<String, Object> params, Map<String, Object> input) {
		
    	//输入的用户参数
    	byte[] pbRand_send1 = new byte[128 * 4];
    	byte[] pbBN_p1 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbRand_send1);
    		SecureRandomUtils.secureRandom().nextBytes(pbBN_p1);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbRand_send1);
//			SecureRandom.getInstanceStrong().nextBytes(pbBN_p1);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
		
		//输入的会话参数
		byte[] pbBN_k1 = (byte[])session.getAttribute(PB_BN_K1);
		byte[] pbEC_R1 = (byte[])session.getAttribute(PB_EC_R1);
		byte[] pbBN_e = (byte[])session.getAttribute(DATA_HASH);
		byte[] pbBN_x1 = (byte[])session.getAttribute(P1_SK);
		byte[] pbMultPK = (byte[])session.getAttribute(MULT_PK);
		
		//输入的过程参数
		String oppo_pbEC_R1_Hex = (String)params.get(PB_EC_R1);
    	byte[] oppo_pbEC_R1 = HexUtil.hexToByteArray(oppo_pbEC_R1_Hex);
    	String oppo_pbZK_P1_Hex = (String)params.get(PB_ZK_P1);
    	byte[] oppo_pbZK_P1 = HexUtil.hexToByteArray(oppo_pbZK_P1_Hex);
    	
    	//调用算法
    	ReturnGetR returnGetR = NativeECDSA.ECDSA_DiCo_Sign_Part1_GetR(pbBN_k1, pbEC_R1, oppo_pbEC_R1, oppo_pbZK_P1);
    	ReturnSend returnSend = NativeECDSA.ECDSA_DiCo_Sign_Part2_Send(pbBN_e, returnGetR.getPbBN_r(), pbBN_x1, pbBN_k1, pbBN_p1, pbMultPK, pbRand_send1);
    	
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(false);
		
		//需要传递的会话
		session.setAttribute(SIGN_R, returnGetR.getPbBN_r());
		session.setAttribute(PB_MP_By_P1, returnSend.getPbMP_ByP1());
		
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_MP_To_P2, HexUtil.getHexString(returnSend.getPbMP_ToP2()));
		computeResult.getToOthers().put(PARTY_P2, toMap);
		return computeResult;
	}
	
	
	private ComputeResult step4( Session session, Map<String, Object> params, Map<String, Object> input) {
		
    	//输入的用户参数
    	byte[] pbRand_send2 = new byte[160 * 4];
    	byte[] pbBN_p2 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbRand_send2);
    		SecureRandomUtils.secureRandom().nextBytes(pbBN_p2);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbRand_send2);
//			SecureRandom.getInstanceStrong().nextBytes(pbBN_p2);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
		
		//输入的会话参数
		byte[] pbBN_k2 = (byte[])session.getAttribute(PB_BN_K2);
		byte[] pbBN_r = (byte[])session.getAttribute(SIGN_R);
		byte[] pbBN_e = (byte[])session.getAttribute(DATA_HASH);
		byte[] pbBN_x2 = (byte[])session.getAttribute(P2_SK);
		byte[] pbMultPK = (byte[])session.getAttribute(MULT_PK);
		
		//输入的过程参数
		String pbMP_ToP2_Hex = (String)params.get(PB_MP_To_P2);
    	byte[] pbMP_ToP2 = HexUtil.hexToByteArray(pbMP_ToP2_Hex);

    	//调用算法
    	ReturnMult returnMult = NativeECDSA.ECDSA_DiCo_Sign_Part2_Mult(pbBN_e, pbBN_r, pbBN_x2, pbBN_k2, pbBN_p2, pbMultPK, pbMP_ToP2, pbRand_send2);
		
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(false);

		
		//需要传递的会话
		session.setAttribute(PB_BN_ALPHA2, returnMult.getPbBN_alpha2());
		session.setAttribute(PB_BN_BETA2, returnMult.getPbBN_beta2());
		
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_MP_To_P1, HexUtil.getHexString(returnMult.getPbMP_ToP1()));
		toMap.put(PB_BN_ALPHA2, HexUtil.getHexString(returnMult.getPbBN_alpha2()));
		toMap.put(PB_BN_BETA2, HexUtil.getHexString(returnMult.getPbBN_beta2()));
		computeResult.getToOthers().put(PARTY_P1, toMap);
		return computeResult;
	}
	

	private ComputeResult step5(Session session, Map<String, Object> params, Map<String, Object> input) {
    	//输入的用户参数
    	byte[] pbRand_send2 = new byte[128 * 4];
    	byte[] pbBN_p2 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbRand_send2);
    		SecureRandomUtils.secureRandom().nextBytes(pbBN_p2);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbRand_send2);
//			SecureRandom.getInstanceStrong().nextBytes(pbBN_p2);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
		
		//输入的会话参数
		byte[] pbMP_ByP1 = (byte[])session.getAttribute(PB_MP_By_P1);
		byte[] pbBN_r = (byte[])session.getAttribute(SIGN_R);
    	byte[] pbMultSK = (byte[])session.getAttribute(MULT_SK);
		
		//输入的过程参数
		String pbMP_ToP1_Hex = (String)params.get(PB_MP_To_P1);
    	byte[] pbMP_ToP1 = HexUtil.hexToByteArray(pbMP_ToP1_Hex);
		String pbBN_alpha2_Hex = (String)params.get(PB_BN_ALPHA2);
    	byte[] pbBN_alpha2 = HexUtil.hexToByteArray(pbBN_alpha2_Hex);
		String pbBN_beta2_Hex = (String)params.get(PB_BN_BETA2);
    	byte[] pbBN_beta2 = HexUtil.hexToByteArray(pbBN_beta2_Hex);
    	
    	//调用算法
    	ReturnRecv returnRecv = NativeECDSA.ECDSA_DiCo_Sign_Part2_Recv(pbMultSK, pbMP_ByP1, pbMP_ToP1);
    	ReturnGetS returnGetS = NativeECDSA.ECDSA_DiCo_Sign_Part2_GetS(returnRecv.getPbBN_alpha1(), returnRecv.getPbBN_beta1(), pbBN_alpha2, pbBN_beta2);
    	
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(true);
		
		//输出的结果
		computeResult.getResult().put(SIGN_R, HexUtil.getHexString(pbBN_r));
		computeResult.getResult().put(SIGN_S, HexUtil.getHexString(returnGetS.getPbBN_s()));
		
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_BN_ALPHA1, HexUtil.getHexString(returnRecv.getPbBN_alpha1()));
		toMap.put(PB_BN_BETA1, HexUtil.getHexString(returnRecv.getPbBN_beta1()));
		computeResult.getToOthers().put(PARTY_P2, toMap);
		return computeResult;
	}
	
	
	private ComputeResult step6(Session session, Map<String, Object> params, Map<String, Object> input) {		
		//输入的会话参数
		byte[] pbBN_alpha2 = (byte[])session.getAttribute(PB_BN_ALPHA2);
		byte[] pbBN_beta2 = (byte[])session.getAttribute(PB_BN_BETA2);
		byte[] pbBN_r = (byte[])session.getAttribute(SIGN_R);
		
		//输入的过程参数
		String pbBN_alpha1_Hex = (String)params.get(PB_BN_ALPHA1);
    	byte[] pbBN_alpha1 = HexUtil.hexToByteArray(pbBN_alpha1_Hex);
		String pbBN_beta1_Hex = (String)params.get(PB_BN_BETA1);
    	byte[] pbBN_beta1 = HexUtil.hexToByteArray(pbBN_beta1_Hex);
    	
    	//调用算法
    	ReturnGetS returnGetS = NativeECDSA.ECDSA_DiCo_Sign_Part2_GetS(pbBN_alpha1, pbBN_beta1, pbBN_alpha2, pbBN_beta2);
    	
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(true);
		
		//输出的结果
		computeResult.getResult().put(SIGN_R, HexUtil.getHexString(pbBN_r));
		computeResult.getResult().put(SIGN_S, HexUtil.getHexString(returnGetS.getPbBN_s()));
		
		return computeResult;
	}
	

}
