package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;

import org.elasticsearch.common.settings.Settings;

public class MyOwnAuditLog extends AbstractAuditLog {
   
	public MyOwnAuditLog(Settings settings) {
        super(settings);
    }

    @Override
	public void close() throws IOException {
		
	}

	@Override
	protected void save(AuditMessage msg) {
	}

}
