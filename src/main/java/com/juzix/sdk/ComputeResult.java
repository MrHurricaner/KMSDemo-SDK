package com.juzix.sdk;

import java.util.HashMap;
import java.util.Map;

public class ComputeResult {

	private boolean isFinshed;
	private Map<String, Object> result = new HashMap<>();
	private Map<String, Map<String, Object>> toOthers = new HashMap<>();
	private String atrribute;

	public Map<String, Map<String, Object>> getToOthers() {
		return toOthers;
	}
	public void setToOthers(Map<String, Map<String, Object>> toOthers) {
		this.toOthers = toOthers;
	}
	public boolean isFinshed() {
		return isFinshed;
	}
	public void setFinshed(boolean isFinshed) {
		this.isFinshed = isFinshed;
	}
	public Map<String, Object> getResult() {
		return result;
	}
	public void setResult(Map<String, Object> result) {
		this.result = result;
	}
	public String getAtrribute() {
		return atrribute;
	}
	public void setAtrribute(String atrribute) {
		this.atrribute = atrribute;
	}
	@Override
	public String toString() {
		return "ComputeResult [isFinshed=" + isFinshed + ", result=" + result + ", toOthers=" + toOthers
				+ ", atrribute=" + atrribute + "]";
	}

}
