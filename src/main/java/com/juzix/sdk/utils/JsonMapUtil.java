package com.juzix.sdk.utils;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class JsonMapUtil {

    private static Map<String, Object> jsonToMap(JSONObject jsonResult) throws JSONException {
        Map<String, Object> result = new HashMap<String, Object>();
        if (jsonResult != null) {
            Iterator<String> keyIt = jsonResult.keys();
            while (keyIt.hasNext()) {
                String key = keyIt.next();
                Object val = jsonResult.get(key);
                if (val != null) {
                    if (val instanceof JSONObject) {
                        Map<String, Object> valMap = jsonToMap((JSONObject) val);
                        result.put(key, valMap);
                    } else {
                        result.put(key, val);
                    }
                } else {
                    result.put(key, null);
                }
            }
        }
        return result;
    }

    /**
     * json转Map<String, Map<String, Object>>
     *
     * @param toMap
     * @return
     * @throws JSONException
     */
    public static Map<String, Map<String, Object>> toMap(String toMap) throws JSONException {
        JSONObject json = new JSONObject(toMap);
        Map<String, Map<String, Object>> result = new HashMap<String, Map<String, Object>>();
        if (json != null) {
            Iterator<String> keyIt = json.keys();
            while (keyIt.hasNext()) {
                String key = keyIt.next();
                Object val = json.get(key);
                if (val != null) {
                    if (val instanceof JSONObject) {
                        Map<String, Object> valMap = jsonToMap((JSONObject) val);
                        result.put(key, valMap);
                    } else {
                        throw new RuntimeException("转换异常");
                    }
                } else {
                    result.put(key, null);
                }
            }
        }
        return result;
    }

    /**
     * map转json字符串
     *
     * @param map
     * @return
     */
    public static String toJson(Map<String, Map<String, Object>> map) {
        JSONObject json = new JSONObject(map);
        return json.toString();
    }

    public static void main(String[] args) {
        String result = "{\"P2\":{\"pbMultPK\":\"D9BCB02D642185285E960E64B9BCF6DEFD90A12FB5879CDF711FBA09E4BD05A23E9185943985068FF70A8B21BEB76E8B3F073D2D5DDA5D1F70B1882F32636A80DA348DB00D8F1BF30A13F56E5F655CAB3E6DDEB20FC86B04F36577302962CA4C48C632690C68404C92350844C0A4963D822BB959CA8211AEECED31D710454A03\",\"pbP1_PK\":\"480C74D85E7DF319DC957C7F0275133ACC52ABA86910143BFCDD0AC7C635282732AED7F91CE3146729ADA05EBA6A3F085DE8227301A02BFC29812C2D9A1C7E44\",\"_MpcSdk_step\":1,\"_MpcSdk_sessionId\":\"9c4fcd58-29a5-4199-9bf1-a219708da76a\",\"pbP1_ZK\":\"99091D89DA27440E65053066B35D7D0F8744FCFEB848A6A51A4134BF4BC8BD654C72C35DCC0218B1CC40A5F14665C439CFD9108B54E9D5BF9E048E5C5A408B32\",\"_MpcSdk_computeKey\":\"ECDSAKeyGen\"}}";

        Map<String, Map<String, Object>> getToOther = null;
        try {
            getToOther = (Map<String, Map<String, Object>>) toMap(result);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        System.out.println(getToOther.get("P2").get("pbMultPK"));

        System.out.println(toJson(getToOther));
    }
}

