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

import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;

public abstract class AbstractAuditLog implements AuditLog {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final IndexNameExpressionResolver resolver;
    protected final Provider<ClusterService> clusterService;
    protected final Settings settings;
    protected final boolean withRequestDetails;

    protected AbstractAuditLog(Settings settings, final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService) {
        super();
                
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        
        String[] disabledCategories = settings.getAsArray("searchguard.audit.config.disabled_categories", new String[]{});
        withRequestDetails = settings.getAsBoolean("searchguard.audit.enable_request_details", false);
        
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
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.FAILED_LOGIN, "User: "+username, username, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logFailedLogin(final String username, final RestRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.FAILED_LOGIN, "User: "+username, username, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logMissingPrivileges(final String privilege, final TransportRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.MISSING_PRIVILEGES, "Privilege: "+privilege, privilege, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logBadHeaders(final TransportRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logBadHeaders(final RestRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSgIndexAttempt(final TransportRequest request, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SG_INDEX_ATTEMPT, "Action: "+action, action, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSSLException(final TransportRequest request, final Throwable t, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSSLException(final RestRequest request, final Throwable t, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }
    
    @Override
    public void logAuthenticatedRequest(TransportRequest request, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.AUTHENTICATED, "Action: " + action, action, request
                ,withRequestDetails, resolver, clusterService, this.settings));
    }

    protected void checkAndSave(final ContextAndHeaderHolder request, String action, final AuditMessage msg) {
        
        if(action != null 
                && 
                ( action.startsWith("internal:")
                  || action.contains("]") //shard level acions
                  || action.startsWith("cluster:monitor")
                  || action.startsWith("indices:monitor")
                )
                && msg.category != Category.MISSING_PRIVILEGES
                && msg.category != Category.FAILED_LOGIN
                && msg.category != Category.SG_INDEX_ATTEMPT) {
            
        
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {}", msg.toPrettyString());
            }
        
            return;
        }
        
        if (msg.getCategory().isEnabled()) {
        	save(msg);        	
        }
    }

    protected abstract void save(final AuditMessage msg);

}
