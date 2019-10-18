package com.juzix.sdk;

import java.util.concurrent.ConcurrentHashMap;

public class DefaultSession implements Session {
	
	private ConcurrentHashMap<String, Object> attrs = new ConcurrentHashMap<String, Object>();
	private String id;

	@Override
	public String getId() {
		return id;
	}

	@Override
	public void setId(String id) {
		this.id = id;
	}

	@Override
	public Object getAttribute(String key) {
		return attrs.get(key);
	}

	@Override
	public void setAttribute(String key, Object value) {
		attrs.put(key, value);
	}

	@Override
	public Object removeAttribute(String key) {
		return attrs.remove(key);
	}
	
}
