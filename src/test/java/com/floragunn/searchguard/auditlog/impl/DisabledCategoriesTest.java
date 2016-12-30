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

import static org.hamcrest.CoreMatchers.containsString;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

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
	public void completetlyInvalidConfigurationTest() throws Exception {
		Builder settingsBuilder = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		settingsBuilder.put("searchguard.audit.config.disabled_categories", "nonexistant");
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null);
		logAll(auditLog);
		
		auditLog.pool.shutdown();
		auditLog.pool.awaitTermination(10, TimeUnit.SECONDS);

		String result = capture.getResult();
		Assert.assertTrue(categoriesPresentInLog(result, Category.values()));
		
	}

	@Test
	public void invalidConfigurationTest() {
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		settingsBuilder.put("searchguard.audit.config.disabled_categories", "nonexistant, bad_headers");
		AuditLog auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null);
		logAll(auditLog);
		String result = capture.getResult();
		Assert.assertFalse(categoriesPresentInLog(result, Category.BAD_HEADERS));		
	}
	
	@Test
	public void enableAllCategoryTest() throws Exception {
		Builder settingsBuilder  = Settings.settingsBuilder();
		settingsBuilder.put("searchguard.audit.type", "debug");
		
		// we use the debug output, no ES client is needed. Also, we 
		// do not need to close.		
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null);
		
		logAll(auditLog);
		
		// we're using the ExecutorService in AuditLogImpl, so we need to wait
		// until all tasks are finished before we can check the result
		auditLog.pool.shutdown();
		auditLog.pool.awaitTermination(10, TimeUnit.SECONDS);
		
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
	public void disableSingleCategoryTest() throws Exception {
		for (Category category : Category.values()) {
			checkCategoriesDisabled(category);
			resetCategories.resetCategories();
		}
	}

	@Test
	public void disableAllCategoryTest() throws Exception{
		checkCategoriesDisabled(Category.values());
	}
	
	@Test
	public void disableSomeCategoryTest() throws Exception{
		checkCategoriesDisabled(Category.AUTHENTICATED, Category.BAD_HEADERS, Category.FAILED_LOGIN);
	}
	
	@After
	public void restoreOut() {
		System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
	}
	
	protected void checkCategoriesDisabled(Category ... disabledCategories) throws Exception {

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
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null);
		
		logAll(auditLog);
		
		auditLog.pool.shutdown();
		auditLog.pool.awaitTermination(10, TimeUnit.SECONDS);

		String result = capture.getResult();
				
		List<Category> allButDisablesCategories = new LinkedList(Arrays.asList(Category.values()));
		allButDisablesCategories.removeAll(Arrays.asList(disabledCategories));
		
		Assert.assertFalse(categoriesPresentInLog(result, disabledCategories));
		Assert.assertTrue(categoriesPresentInLog(result, allButDisablesCategories.toArray(new Category[] {})));
	}
		
	protected boolean categoriesPresentInLog(String result, Category ... categories) {
		// since we're logging a JSON structure, whitespaces between keys and
		// values must not matter
		result = result.replaceAll(" ", "");
		for (Category category : categories) {
			if(!result.contains("\""+AuditMessage.AuditMessageKey.CATEGORY+"\":\""+category.name()+"\"")) {
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
