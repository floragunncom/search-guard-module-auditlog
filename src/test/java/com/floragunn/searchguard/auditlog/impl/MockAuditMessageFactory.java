/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.auditlog.impl;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auditlog.MockRestRequest;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class MockAuditMessageFactory {
	
	public static AuditMessage validAuditMessage() {
		ContextAndHeaderHolder holder = createValidRestRequest();
		Category category = Category.FAILED_LOGIN;
		String reason = "Forbidden";
		String details = "Details";
		AuditMessage msg = new AuditMessage(category, reason, details, holder, true, null, null, Settings.EMPTY);
		return msg;
	}

	private static ContextAndHeaderHolder createValidRestRequest() {
		Map<String, Object> context = new HashMap<>();	
		User user = new User("John Doe");
		context.put(ConfigConstants.SG_USER, user);
		context.put(ConfigConstants.SG_REMOTE_ADDRESS, "8.8.8.8");
		context.put(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE");
		return new MockRestRequest(new HashMap<String, String>(), context);
	}
}
