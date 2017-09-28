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

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auditlog.MockRestRequest;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class MockAuditMessageFactory {
	
	public static AuditMessage validAuditMessage() {
	    RestRequest holder = createValidRestRequest();
		Category category = Category.FAILED_LOGIN;
		String reason = "Forbidden";
		String details = "Details";
		
		ThreadContext tc = new ThreadContext(Settings.EMPTY);
		User user = new User("John Doe");
		tc.putTransient(ConfigConstants.SG_USER, user);
		tc.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, "8.8.8.8");
		tc.putTransient(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE");
		
		AuditMessage msg = new AuditMessage(category, null, Origin.TRANSPORT);
		return msg;
	}

	private static RestRequest createValidRestRequest() {
		return new MockRestRequest();
	}
}
