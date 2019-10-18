package com.juzix.sdk;

import com.juzix.kms.SecureRandomUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MpcSdk {

    public final static String MPC_KEY_COMPUTEKEY = "_MpcSdk_computeKey";
    public final static String MPC_KEY_STEP = "_MpcSdk_step";
    public final static String MPC_KEY_SESSIONID = "_MpcSdk_sessionId";
    public final static String MPC_KEY_ATTRIBUTE = "_MpcSdk_attribute";

    private static Map<String, Compute> computes = new HashMap<>();
    private static ConcurrentHashMap<String, MpcSdk> partyMap = new ConcurrentHashMap<>();

    private SessionDao sessionDao;
    private String ownerPartyKey;

    private MpcSdk() {

    }

    private MpcSdk(SessionDao sessionDao) {
        this.sessionDao = sessionDao;
    }

    static {
        Compute ecdsa_keygen = new ComputeEcdsaKeyGen();
        Compute ecdsa_sign = new ComputeEcdsaSign();
        computes.put(ecdsa_keygen.getKey(), ecdsa_keygen);
        computes.put(ecdsa_sign.getKey(), ecdsa_sign);
    }


    public static MpcSdk getMpcSdk(String ownerPartyKey) {
        return getMpcSdk(ownerPartyKey, new MemorySessionDao());
    }

    /**
     * 获得随机数
     *
     * @param rand
     */
    public static void getRandom(byte[] rand) {
        SecureRandomUtils.secureRandom().nextBytes(rand);
    }


    public synchronized static MpcSdk getMpcSdk(String ownerPartyKey, SessionDao sessionDao) {
        MpcSdk mpcSdk = partyMap.get(ownerPartyKey);
        if (mpcSdk == null) {
            mpcSdk = new MpcSdk(sessionDao);
            mpcSdk.ownerPartyKey = ownerPartyKey;
            partyMap.put(ownerPartyKey, mpcSdk);
        }
        return mpcSdk;
    }


    public MpcContext createSession(String computeKey) {
        Compute compute = computes.get(computeKey);
        if (compute == null) {
            return null;
        }
        Session session = new DefaultSession();
        session.setAttribute(MPC_KEY_STEP, 0);

        sessionDao.create(session);

        MpcContext mpcParam = new MpcContext();

        Map<String, Object> param = new HashMap<>();
        param.put(MPC_KEY_COMPUTEKEY, computeKey);
        param.put(MPC_KEY_SESSIONID, session.getId());
        param.put(MPC_KEY_STEP, 0);

        mpcParam.getToOthers().put(compute.beginParty(), param);

        return mpcParam;
    }


    public MpcContext nextStep(Map<String, Map<String, Object>> processData, Map<String, Object> input, String atrribute) {
        Map<String, Object> mpcParam = processData.get(ownerPartyKey);
        if (mpcParam == null) {
            throw new RuntimeException("错误的接收者");
        }

        int step = new Double(mpcParam.get(MPC_KEY_STEP).toString()).intValue();
        int nextStep = step + 1;
        String sessoinId = (String) mpcParam.get(MPC_KEY_SESSIONID);
        Session session = sessionDao.readSession(sessoinId);
        if (session == null) {
            session = new DefaultSession();
            session.setId(sessoinId);
            session.setAttribute(MPC_KEY_STEP, step);
        }
        if (atrribute != null) {
            session.setAttribute(MPC_KEY_ATTRIBUTE, atrribute);
        }

        Compute compute = computes.get(mpcParam.get(MPC_KEY_COMPUTEKEY));

        ComputeResult computeResult = compute.nextStep(nextStep, session, mpcParam, input);

        if (computeResult.isFinshed()) {
            sessionDao.delete(session);
        } else {
            sessionDao.update(session);
        }

        MpcContext result = new MpcContext();
        result.setFinshed(computeResult.isFinshed());
        result.setResult(computeResult.getResult());
        result.setToOthers(computeResult.getToOthers());

        for (String key : result.getToOthers().keySet()) {
            result.getToOthers().get(key).put(MPC_KEY_COMPUTEKEY, mpcParam.get(MPC_KEY_COMPUTEKEY));
            result.getToOthers().get(key).put(MPC_KEY_SESSIONID, sessoinId);
            result.getToOthers().get(key).put(MPC_KEY_STEP, nextStep);
        }

        return result;
    }

    public MpcContext nextStep(Map<String, Map<String, Object>> processData) {
        return nextStep(processData, new HashMap<String, Object>());
    }

    public MpcContext nextStep(Map<String, Map<String, Object>> processData, Map<String, Object> input) {
        return nextStep(processData, input, null);
    }

    public MpcContext nextStep(Map<String, Map<String, Object>> processData, String atrribute) {
        return nextStep(processData, new HashMap<String, Object>(), atrribute);
    }

    public String getAtrribute(Map<String, Map<String, Object>> processData) {
        Map<String, Object> mpcParam = processData.get(ownerPartyKey);
        if (mpcParam == null) {
            throw new RuntimeException("错误的接收者");
        }
        String sessoinId = (String) mpcParam.get(MPC_KEY_SESSIONID);
        Session session = sessionDao.readSession(sessoinId);
        if (session == null) {
            return null;
        }

        Object atrObj = session.getAttribute(MPC_KEY_ATTRIBUTE);
        if (atrObj == null) {
            return null;
        }
        return atrObj.toString();
    }
}
