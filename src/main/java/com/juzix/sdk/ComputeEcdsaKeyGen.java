package com.juzix.sdk;

import java.util.HashMap;
import java.util.Map;

import com.juzix.kms.HexUtil;
import com.juzix.kms.NativeECDSA;
import com.juzix.kms.NativeECDSA.ReturnKeyGenDone;
import com.juzix.kms.NativeECDSA.ReturnKeyGenRecv;
import com.juzix.kms.NativeECDSA.ReturnKeyGenSend;
import com.juzix.kms.SecureRandomUtils;

public class ComputeEcdsaKeyGen implements Compute {
	
	public final static String COMPUTE_KEY = "ECDSAKeyGen";
	
	public final static String PARTY_P1 = "P1";
	public final static String PARTY_P2 = "P2";
	
	public final static String P1_SK = "pbP1_SK";	
	public final static String P2_SK = "pbP2_SK";
	public final static String MULT_SK = "pbMultSK";	
	public final static String MULT_PK = "pbMultPK";
	public final static String PUBKEY = "pbPubKey";
	
	public final static String PB_P1_PK = "pbP1_PK";
	public final static String PB_P1_ZK = "pbP1_ZK";
	public final static String PB_P2_PK = "pbP2_PK";
	public final static String PB_P2_ZK = "pbP2_ZK";

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
		default:
			return null;
		}
	}
	
	private ComputeResult step1( Session session, Map<String, Object> params, Map<String, Object> input) {
    	//输入的用户参数
		String pbP1_SK_Hex = (String)input.get(P1_SK);
    	byte[] pbP1_SK = HexUtil.hexToByteArray(pbP1_SK_Hex);
    	byte [] pbRand1 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbRand1);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbRand1);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}
    	
    	//调用算法
		ReturnKeyGenSend returnKeyGenSend = NativeECDSA.ECDSA_DiCo_KeyGen_P1_Send(pbP1_SK, pbRand1);
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(false);
		
		//需要传递的会话
		session.setAttribute(P1_SK, pbP1_SK);
		session.setAttribute(PB_P1_PK, returnKeyGenSend.getPbP1_PK());
		session.setAttribute(PB_P1_ZK, returnKeyGenSend.getPbP1_ZK());
		session.setAttribute(MULT_SK, returnKeyGenSend.getPbMultSK());
		session.setAttribute(MULT_PK, returnKeyGenSend.getPbMultPK());
		
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_P1_PK, HexUtil.getHexString(returnKeyGenSend.getPbP1_PK()));
		toMap.put(PB_P1_ZK, HexUtil.getHexString(returnKeyGenSend.getPbP1_ZK()));
		toMap.put(MULT_PK, HexUtil.getHexString(returnKeyGenSend.getPbMultPK()));
		computeResult.getToOthers().put(PARTY_P2, toMap);
		
		return computeResult;
	}
	
	
	private ComputeResult step2(Session session, Map<String, Object> params, Map<String, Object> input) {
		//输入的过程参数
		String pbP1_PK_Hex = (String)params.get(PB_P1_PK);
    	byte[] pbP1_PK = HexUtil.hexToByteArray(pbP1_PK_Hex);
		String pbP1_ZK_Hex = (String)params.get(PB_P1_ZK);
    	byte[] pbP1_ZK = HexUtil.hexToByteArray(pbP1_ZK_Hex);
		String pbMultPK_Hex = (String)params.get(MULT_PK);
    	byte[] pbMultPK = HexUtil.hexToByteArray(pbMultPK_Hex);
    	
    	//输入的用户参数
		String pbP2_SK_Hex = (String)input.get(P2_SK);
    	byte[] pbP2_SK = HexUtil.hexToByteArray(pbP2_SK_Hex);
    	byte [] pbRand2 = new byte[32];
//    	try {
    		SecureRandomUtils.secureRandom().nextBytes(pbRand2);
    		
//			SecureRandom.getInstanceStrong().nextBytes(pbRand2);
//		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
//		}

    	//调用算法
    	ReturnKeyGenDone returnKeyGenDone = NativeECDSA.ECDSA_DiCo_KeyGen_P2_Done(pbMultPK, pbP2_SK, pbP1_PK, pbP1_ZK, pbRand2);
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(true);
    	
		//输出的结果
		computeResult.getResult().put(PUBKEY, HexUtil.getHexString(returnKeyGenDone.getPbPubKey()));
		computeResult.getResult().put(MULT_PK, pbMultPK_Hex);
    	
		//输出的过程参数
		Map<String, Object> toMap =  new HashMap<>();
		toMap.put(PB_P2_PK, HexUtil.getHexString(returnKeyGenDone.getPbP2_PK()));
		toMap.put(PB_P2_ZK, HexUtil.getHexString(returnKeyGenDone.getPbP2_ZK()));
		computeResult.getToOthers().put(PARTY_P1, toMap);

		return computeResult;
	}
	
	
    private ComputeResult step3(Session session, Map<String, Object> params, Map<String, Object> input) {
    	//输入的会话参数
    	byte[] pbMultSK = (byte[])session.getAttribute(MULT_SK);
    	byte[] pbMultPK = (byte[])session.getAttribute(MULT_PK);
    	byte[] pbP1_SK = (byte[])session.getAttribute(P1_SK);
    	byte[] pbP1_PK = (byte[])session.getAttribute(PB_P1_PK);
    	//输入的过程参数
    	byte[] pbP2_PK = HexUtil.hexToByteArray((String)params.get(PB_P2_PK));
    	byte[] pbP2_ZK = HexUtil.hexToByteArray((String)params.get(PB_P2_ZK));

    	//调用算法
    	ReturnKeyGenRecv returnKeyGenRecv = NativeECDSA.ECDSA_DiCo_KeyGen_P1_Recv(pbMultPK, pbP1_SK, pbP1_PK, pbP2_PK, pbP2_ZK);
		ComputeResult computeResult = new ComputeResult();
		computeResult.setFinshed(true);
		
		//输出的结果
		computeResult.getResult().put(PUBKEY, HexUtil.getHexString(returnKeyGenRecv.getPbPubKey()));
		computeResult.getResult().put(MULT_SK, HexUtil.getHexString(pbMultSK));
		computeResult.getResult().put(MULT_PK, HexUtil.getHexString(pbMultPK));
    	
		return computeResult;
	}

}
