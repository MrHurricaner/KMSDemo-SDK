package com.juzix.sdk;

public interface SessionDao {

    String create(Session session);

    Session readSession(String sessionId);

    void update(Session session);

    void delete(Session session);
}
