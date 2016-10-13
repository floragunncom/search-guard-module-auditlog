package com.floragunn.searchguard.auditlog.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.junit.Assert;
import org.junit.Test;

public class DelegateTest  extends AbstractUnitTest  {

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
		Builder settingsBuilder  = Settings.builder();
		settingsBuilder.put("searchguard.audit.type", type);
		settingsBuilder.put("path.home", ".");
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null);
		auditLog.close();
		if (expectedClass != null) {
		    Assert.assertNotNull("delegate is null for type: "+type,auditLog.delegate);
			Assert.assertEquals(expectedClass, auditLog.delegate.getClass());	
		} else {
			Assert.assertNull(auditLog.delegate);
		}
		
	}
}
