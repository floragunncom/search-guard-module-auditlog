package com.floragunn.searchguard.auditlog.impl;

import org.elasticsearch.common.ContextAndHeaderHolder;

import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class MockAuditMessageFactory {
	
	public static AuditMessage validAuditMessage() {
		ContextAndHeaderHolder holder = createValidContext();
		Category category = Category.FAILED_LOGIN;
		String reason = "Forbidden";
		String details = "Details";
		AuditMessage msg = new AuditMessage(category, reason, details, holder);
		return msg;
	}

	private static ContextAndHeaderHolder createValidContext() {
		ContextAndHeaderHolder holder = new ContextAndHeaderHolder();	
		User user = new User("John Doe");
		holder.putInContext(ConfigConstants.SG_USER, user);
		holder.putInContext(ConfigConstants.SG_REMOTE_ADDRESS, "8.8.8.8");
		holder.putInContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE");
		return holder;
	}
}
