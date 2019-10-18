package com.juzix.sdk;

import java.util.Map;

public interface Compute {
	
	String getKey();
	
	String beginParty();

	ComputeResult nextStep(int step, Session session, Map<String, Object> params, Map<String, Object> input);

}
