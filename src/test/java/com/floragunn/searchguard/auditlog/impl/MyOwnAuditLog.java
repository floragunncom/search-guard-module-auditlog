package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

public class MyOwnAuditLog extends AbstractAuditLog {
   
	public MyOwnAuditLog(Settings settings, ThreadPool threadPool) {
        super(settings, threadPool);
    }

    @Override
	public void close() throws IOException {
		
	}

	@Override
	protected void save(AuditMessage msg) {
	}

}
