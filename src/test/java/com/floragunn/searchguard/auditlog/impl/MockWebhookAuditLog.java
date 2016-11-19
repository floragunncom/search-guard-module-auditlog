package com.floragunn.searchguard.auditlog.impl;

import org.elasticsearch.common.settings.Settings;

public class MockWebhookAuditLog extends WebhookAuditLog {
	
	String payload = null;
	String url = null;
	
	MockWebhookAuditLog(Settings settings) {
		super(settings);
	}

	@Override
	boolean doPost(String url, String payload) {
		this.payload = payload;
		return true;
	}
	
	
	@Override
	boolean doGet(String url) {
		this.url = url;
		return true;
	}
}
