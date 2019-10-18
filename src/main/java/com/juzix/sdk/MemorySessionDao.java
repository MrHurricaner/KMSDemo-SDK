package com.juzix.sdk;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class MemorySessionDao implements SessionDao {
	
	private ConcurrentHashMap<String, Session>  memory = new ConcurrentHashMap<String, Session>();
	
	@Override
	public String create(Session session) {
		if(session == null ) {
			return null;
		}
		String id = UUID.randomUUID().toString();
		session.setId(id);
		memory.put(id, session);
		return id;
	}

	@Override
	public Session readSession(String sessionId) {
		return memory.get(sessionId);
	}

	@Override
	public void update(Session session) {
		memory.putIfAbsent(session.getId(), session);
	}

	@Override
	public void delete(Session session) {
		if(session==null || session.getId() == null) {
			return;
		}
		memory.remove(session.getId());
	}

}
