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

import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.WildcardMatcher;

public abstract class AbstractAuditLog implements AuditLog {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final ThreadPool threadPool;
    protected final IndexNameExpressionResolver resolver;
    protected final ClusterService clusterService;
    protected final Settings settings;
    protected final boolean withRequestDetails;
    private final String[] ignoreAuditUsers;

    protected AbstractAuditLog(Settings settings, final ThreadPool threadPool, final IndexNameExpressionResolver resolver, final ClusterService clusterService) {
        super();
        this.threadPool = threadPool;
                
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        
        String[] disabledCategories = settings.getAsArray("searchguard.audit.config.disabled_categories", new String[]{});
        withRequestDetails = settings.getAsBoolean("searchguard.audit.enable_request_details", false);

        ignoreAuditUsers = settings.getAsArray("searchguard.audit.ignore_users", new String[]{});
        if (ignoreAuditUsers.length > 0) {
            log.info("Configured Users to ignore: {}", Arrays.toString(ignoreAuditUsers));
        }
        
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
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logFailedLogin(final String username, final RestRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.FAILED_LOGIN, "User: "+username, username, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logMissingPrivileges(final String privilege, final TransportRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.MISSING_PRIVILEGES, "Privilege: "+privilege, privilege, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logBadHeaders(final TransportRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logBadHeaders(final RestRequest request) {
        checkAndSave(request, null, new AuditMessage(AuditMessage.Category.BAD_HEADERS, null, null, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSgIndexAttempt(final TransportRequest request, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SG_INDEX_ATTEMPT, "Action: "+action, action, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSSLException(final TransportRequest request, final Throwable t, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    @Override
    public void logSSLException(final RestRequest request, final Throwable t, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.SSL_EXCEPTION, action, t, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }
    
    @Override
    public void logAuthenticatedRequest(TransportRequest request, final String action) {
        checkAndSave(request, action, new AuditMessage(AuditMessage.Category.AUTHENTICATED, "Action: " + action, action, request
                ,threadPool.getThreadContext(), withRequestDetails, resolver, clusterService, this.settings));
    }

    protected boolean checkActionAndCategory(String action, final AuditMessage msg) {
        
        if(action != null 
                && 
                ( action.startsWith("internal:")
                  || action.contains("]") //shard level actions
                  || action.startsWith("cluster:monitor")
                  || action.startsWith("indices:monitor")
                )
                && msg.category != Category.MISSING_PRIVILEGES
                && msg.category != Category.FAILED_LOGIN
                && msg.category != Category.SG_INDEX_ATTEMPT) {
            
        
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {}", msg.toPrettyString());
            }
        
            return false;
        }

        if (ignoreAuditUsers.length > 0 && WildcardMatcher.matchAny(ignoreAuditUsers, msg.getUser())) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {} because user {} is ignored", msg.toPrettyString(), msg.getUser());
            }
            
            return false;
        }
        
        if (msg.getCategory().isEnabled()) {
        	return true;      	
        } else {
            if(log.isTraceEnabled()) {
                log.trace(msg.getCategory()+ " not enabled");
            }
        }
        
        return false;
    }
    
    protected void checkAndSave(TransportRequest request, String action, final AuditMessage msg) {
        if (checkActionAndCategory(action, msg)) {
            save(msg);          
        } 
    }
    
    protected void checkAndSave(RestRequest request, String action, final AuditMessage msg) {
        if (checkActionAndCategory(action, msg)) {
            save(msg);          
        } 
    }

    protected abstract void save(final AuditMessage msg);

    protected String getExpandedIndexName(DateTimeFormatter indexPattern, String index) {
        if(indexPattern == null) {
            return index;
        }
        return indexPattern.print(DateTime.now(DateTimeZone.UTC));
    }
}
