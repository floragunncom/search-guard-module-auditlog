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

import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;

public abstract class AbstractAuditLog implements AuditLog {

    protected final ESLogger log = Loggers.getLogger(this.getClass());

    protected AbstractAuditLog(Settings settings) {
        super();
                
        String[] disabledCategories = settings.getAsArray("searchguard.audit.config.disabled_categories", new String[]{});
        
        // check if some categories are disabled
        for (String event : disabledCategories) {
        	try {
        		Category category = AuditMessage.Category.valueOf(event.toUpperCase());
        		category.setEnabled(false);
        	} catch(IllegalArgumentException iae) {
        		log.error("Unkown category {}, please check searchguard.audit.config.disabled_categories settings", event);        		
        	}
		}
    }

    @Override
    public void logFailedLogin(final String username, final TransportRequest request) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.FAILED_LOGIN, username, null, request));
    }

    @Override
    public void logFailedLogin(final String username, final RestRequest request) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.FAILED_LOGIN, username, null, request));
    }

    @Override
    public void logMissingPrivileges(final String privilege, final TransportRequest request) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.MISSING_PRIVILEGES, privilege, null, request));
    }

    @Override
    public void logBadHeaders(final TransportRequest request) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request));
    }

    @Override
    public void logBadHeaders(final RestRequest request) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request));
    }

    @Override
    public void logSgIndexAttempt(final TransportRequest request, final String action) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.SG_INDEX_ATTEMPT, action, null, request));
    }

    @Override
    public void logSSLException(final TransportRequest request, final Throwable t, final String action) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request));
    }

    @Override
    public void logSSLException(final RestRequest request, final Throwable t, final String action) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request));
    }
    
    @Override
    public void logAuthenticatedRequest(TransportRequest request, final String action) {
        checkAndSave(request, new AuditMessage(AuditMessage.Category.AUTHENTICATED, action, null, request));
    }

    protected void checkAndSave(final ContextAndHeaderHolder request, final AuditMessage msg) {
        if (msg.getCategory().isEnabled()) {
        	save(msg);        	
        }
    }

    protected abstract void save(final AuditMessage msg);

}
