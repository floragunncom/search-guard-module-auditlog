package com.floragunn.searchguard.auditlog.impl;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.junit.Assert;
import org.junit.Test;

public class DelegateTest  extends AbstractUnitTest  {
	
	protected final ESLogger log = Loggers.getLogger(this.getClass());

	@Test
	public void auditLogTypeTest() throws Exception{
		testAuditType("DeBUg", DebugAuditLog.class);
		testAuditType("intERnal_Elasticsearch", ESAuditLog.class);
		testAuditType("EXTERnal_Elasticsearch", HttpESAuditLog.class);
		testAuditType("com.floragunn.searchguard.auditlog.impl.MyOwnAuditLog", MyOwnAuditLog.class);
		testAuditType("Com.Floragunn.searchguard.auditlog.impl.MyOwnAuditLog", null);
		testAuditType("idonotexist", null);
	}
		
	private void testAuditType(String type, Class<? extends AbstractAuditLog> expectedClass) throws Exception {
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", type);
		settingsBuilder.put("path.home", ".");
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null);
		auditLog.close();
		if (expectedClass != null) {
			Assert.assertTrue(auditLog.delegate.getClass().equals(expectedClass));	
		} else {
			Assert.assertTrue(auditLog.delegate == null);
		}
		
	}
}
