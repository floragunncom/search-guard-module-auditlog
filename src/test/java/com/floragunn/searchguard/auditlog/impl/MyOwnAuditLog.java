package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;

public class MyOwnAuditLog extends AbstractAuditLog {

	@Override
	public void close() throws IOException {
		
	}

	@Override
	protected void save(AuditMessage msg) {
	}

}
