package com.juzix.sdk;

public interface Session {
	
	/**
	 * 获得会话标识
	 * @return 会话标识
	 */
    String getId();
    
    /**
     * 关联session id
     * @param id
     */
    void setId(String id);

    /**
     * 获得属性值
     * @param key 
     * @return
     */
    Object getAttribute(String key);

    /**
     * 设置属性值
     * @param key
     * @param value
     */
    void setAttribute(String key, Object value);
    
    /**
     * 移除属性
     * @param key
     * @return
     */
    Object removeAttribute(String key);
}
