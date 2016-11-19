package com.floragunn.searchguard.auditlog.impl;

import static org.hamcrest.CoreMatchers.containsString;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.transport.TransportRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.CaptureSystemOut;
import com.floragunn.searchguard.auditlog.MockRestRequest;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.google.common.base.Joiner;

public class DisabledCategoriesTest extends AbstractUnitTest  {
	
	protected final ESLogger log = Loggers.getLogger(this.getClass());
	
	@Rule
	public CaptureSystemOut capture = new CaptureSystemOut();
	
	@Rule
	public ResetCategories resetCategories = new ResetCategories();

	@Test
	public void completetlyInvalidConfigurationTest() {
		Builder settingsBuilder = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		settingsBuilder.put("searchguard.audit.config.disabled_categories", "nonexistant");
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null);
		logAll(auditLog);
		String result = capture.getResult();
		Assert.assertTrue(categoriesPresentInLog(result, Category.values()));
		
	}

	@Test
	public void invalidConfigurationTest() {
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		settingsBuilder.put("searchguard.audit.config.disabled_categories", "nonexistant, bad_headers");
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null);
		logAll(auditLog);
		String result = capture.getResult();
		Assert.assertFalse(categoriesPresentInLog(result, Category.BAD_HEADERS));		
	}
	
	@Test
	public void enableAllCategoryTest() {
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		
		// we use the debug output, no ES client is needed. Also, we 
		// do not need to close.		
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null);
		
		logAll(auditLog);
		String result = capture.getResult();
		
		Assert.assertTrue(categoriesPresentInLog(result, Category.values()));
		
		Assert.assertThat(result, containsString("testuser.rest.failedlogin"));
		Assert.assertThat(result, containsString("testuser.transport.failedlogin"));
		Assert.assertThat(result, containsString("privilege.missing"));
		Assert.assertThat(result, containsString("action.indexattempt"));
		Assert.assertThat(result, containsString("action.rest.ssl"));
		Assert.assertThat(result, containsString("action.transport.ssl"));
		Assert.assertThat(result, containsString("action.success"));
				
		System.err.print(capture.getResult());
	}
	
	@Test
	public void disableSingleCategoryTest() {
		for (Category category : Category.values()) {
			checkCategoriesDisabled(category);
			resetCategories.resetCategories();
		}
	}

	@Test
	public void disableAllCategoryTest() {
		checkCategoriesDisabled(Category.values());
	}
	
	@Test
	public void disableSomeCategoryTest() {
		checkCategoriesDisabled(Category.AUTHENTICATED, Category.BAD_HEADERS, Category.FAILED_LOGIN);
	}
	
	@After
	public void restoreOut() {
		System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
	}
	
	protected void checkCategoriesDisabled(Category ... disabledCategories) {
		// todo: Which source level are we officially on? Can I use lambdas here?
		List<String> categoryNames = new LinkedList<>();
		for (Category category : disabledCategories) {
			categoryNames.add(category.name().toLowerCase());
		}
		String disabledCategoriesString = Joiner.on(",").join(categoryNames);
		
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		settingsBuilder.put("searchguard.audit.config.disabled_categories", disabledCategoriesString);
	
		// we use the debug output, no ES client is needed. Also, we 
		// do not need to close.		
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null);
		
		logAll(auditLog);
		String result = capture.getResult();
				
		List<Category> allButDisablesCategories = new LinkedList(Arrays.asList(Category.values()));
		allButDisablesCategories.removeAll(Arrays.asList(disabledCategories));
		
		Assert.assertFalse(categoriesPresentInLog(result, disabledCategories));
		Assert.assertTrue(categoriesPresentInLog(result, allButDisablesCategories.toArray(new Category[] {})));
	}
		
	protected boolean categoriesPresentInLog(String result, Category ... categories) {
		for (Category category : categories) {
			if(!result.contains("\"Category\":\""+category.name()+"\"")) {
				return false;
			}
		}
		return true;
	}
    
	protected void logAll(AuditLog auditLog) {
		logRestFailedLogin(auditLog);
		logTransportFailedLogin(auditLog);
		logMissingPrivileges(auditLog);
		logTransportBadHeaders(auditLog);
		logRestBadHeaders(auditLog);
		logSgIndexAttempt(auditLog);
		logRestSSLException(auditLog);
		logTransportSSLException(auditLog);
		logAuthenticatedRequest(auditLog);
    }
    protected void logRestFailedLogin(AuditLog auditLog) {
    	auditLog.logFailedLogin("testuser.rest.failedlogin", new MockRestRequest());
    }

    protected void logTransportFailedLogin(AuditLog auditLog) {
    	auditLog.logFailedLogin("testuser.transport.failedlogin", new TransportRequest.Empty());
    }

    protected void logMissingPrivileges(AuditLog auditLog) {
    	auditLog.logMissingPrivileges("privilege.missing", new TransportRequest.Empty());
    }

    protected void logTransportBadHeaders(AuditLog auditLog) {
    	auditLog.logBadHeaders(new TransportRequest.Empty());
    }

    protected void logRestBadHeaders(AuditLog auditLog) {
    	auditLog.logBadHeaders(new MockRestRequest());
    }

    protected void logSgIndexAttempt(AuditLog auditLog) {
    	auditLog.logSgIndexAttempt(new TransportRequest.Empty(), "action.indexattempt");
    }

    protected void logRestSSLException(AuditLog auditLog) {
    	auditLog.logSSLException(new MockRestRequest(), new Exception(), "action.rest.ssl");
    }

    protected void logTransportSSLException(AuditLog auditLog) {
    	auditLog.logSSLException(new TransportRequest.Empty(), new Exception(), "action.transport.ssl");
    }
       
    protected void logAuthenticatedRequest(AuditLog auditLog) {
    	auditLog.logAuthenticatedRequest(new TransportRequest.Empty(), "action.success");
    }

}
