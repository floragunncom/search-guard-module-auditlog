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
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;

public abstract class AbstractAuditLog implements AuditLog {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final ThreadPool threadPool;
    protected final IndexNameExpressionResolver resolver;
    protected final ClusterService clusterService;
    protected final Settings settings;
    protected final boolean withRequestDetails;
    protected final boolean resolveBulkRequests;
    private final String[] ignoreAuditUsers;
    private final String[] ignoreAuditRequests;

    protected AbstractAuditLog(Settings settings, final ThreadPool threadPool, final IndexNameExpressionResolver resolver, final ClusterService clusterService) {
        super();
        this.threadPool = threadPool;
                
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        
        final String[] disabledCategories = settings.getAsArray("searchguard.audit.config.disabled_categories", new String[]{});
        withRequestDetails = settings.getAsBoolean("searchguard.audit.enable_request_details", false);
        resolveBulkRequests = settings.getAsBoolean("searchguard.audit.resolve_bulk_requests", true);
        
        ignoreAuditUsers = settings.getAsArray("searchguard.audit.ignore_users", new String[]{});
        if (ignoreAuditUsers.length > 0) {
            log.info("Configured Users to ignore: {}", Arrays.toString(ignoreAuditUsers));
        }
        
        ignoreAuditRequests = settings.getAsArray("searchguard.audit.ignore_requests", new String[]{});
        if (ignoreAuditUsers.length > 0) {
            log.info("Configured Requests to ignore: {}", Arrays.toString(ignoreAuditRequests));
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
    public void logFailedLogin(String effectiveUser, boolean sgadmin, String initiatingUser, TransportRequest request, Task task) {
        final String action = null;
        
        if(!checkFilter(Category.FAILED_LOGIN, action, effectiveUser, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.FAILED_LOGIN, getOrigin(), action, null, effectiveUser, sgadmin, initiatingUser, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }


    @Override
    public void logFailedLogin(String effectiveUser, boolean sgadmin, String initiatingUser, RestRequest request) {
        
        if(!checkFilter(Category.FAILED_LOGIN, effectiveUser, request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.FAILED_LOGIN, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(withRequestDetails && request.hasContentOrSourceParam()) {
            msg.addBody(request.contentOrSourceParam());
        }
        msg.addPath(request.path());
        msg.addInitiatingUser(initiatingUser);
        msg.addEffectiveUser(effectiveUser);
        msg.addIsAdminDn(sgadmin);
        msg.addRestHeaders(request.getHeaders());
        msg.addRestParams(request.params());
        save(msg);
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean sgadmin, String initiatingUser, TransportRequest request, Task task) {
        final String action = null;
        
        if(!checkFilter(Category.AUTHENTICATED, action, effectiveUser, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.AUTHENTICATED, getOrigin(), action, null, effectiveUser, sgadmin, initiatingUser,remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean sgadmin, String initiatingUser, RestRequest request) {
        
        if(!checkFilter(Category.AUTHENTICATED, effectiveUser, request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.AUTHENTICATED, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(withRequestDetails && request.hasContentOrSourceParam()) {
           msg.addBody(request.contentOrSourceParam());
        }
        msg.addPath(request.path());
        msg.addInitiatingUser(initiatingUser);
        msg.addEffectiveUser(effectiveUser);
        msg.addIsAdminDn(sgadmin);
        msg.addRestHeaders(request.getHeaders());
        msg.addRestParams(request.params());
        save(msg);
    }

    @Override
    public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
        final String action = null;
        
        if(!checkFilter(Category.MISSING_PRIVILEGES, privilege, null, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.MISSING_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
        final String action = null;
        
        if(!checkFilter(Category.GRANTED_PRIVILEGES, privilege, null, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.GRANTED_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logBadHeaders(TransportRequest request, String action, Task task) {
        
        if(!checkFilter(Category.BAD_HEADERS, action, null, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.BAD_HEADERS, getOrigin(), action, null, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logBadHeaders(RestRequest request) {
        
        if(!checkFilter(Category.BAD_HEADERS, null, request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.BAD_HEADERS, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(withRequestDetails && request.hasContentOrSourceParam()) {
            msg.addBody(request.contentOrSourceParam());
        }
        msg.addPath(request.path());
        msg.addEffectiveUser(getUser());        
        msg.addRestHeaders(request.getHeaders());
        msg.addRestParams(request.params());

        save(msg);
    }

    @Override
    public void logSgIndexAttempt(TransportRequest request, String action, Task task) {
        
        if(!checkFilter(Category.SG_INDEX_ATTEMPT, action, null, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.SG_INDEX_ATTEMPT, getOrigin(), action, null, null, false, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(TransportRequest request, Throwable t, String action, Task task) { 
        
        if(!checkFilter(Category.SSL_EXCEPTION, action, null, request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.SSL_EXCEPTION, getOrigin(), action, null, null, false, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, t);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(RestRequest request, Throwable t) {
        
        if(!checkFilter(Category.SSL_EXCEPTION, null, request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.SSL_EXCEPTION, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(withRequestDetails && request.hasContentOrSourceParam()) {
            msg.addBody(request.contentOrSourceParam());
        }
        msg.addPath(request.path());
        msg.addException(t);
        msg.addEffectiveUser(getUser());
        msg.addRestHeaders(request.getHeaders());
        msg.addRestParams(request.params());
        save(msg);
    }

    private Origin getOrigin() {
        final String origin = (String) threadPool.getThreadContext().getTransient("_sg_origin");
        return origin == null?null:Origin.valueOf(origin);
    }
    
    private TransportAddress getRemoteAddress() {
        return threadPool.getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
    }
    
    private String getUser() {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.SG_USER);
        return user==null?null:user.getName();
    }
    
    private Map<String, String> getThreadContextHeaders() {
        return threadPool.getThreadContext().getHeaders();
    }
    
    private boolean checkFilter(final Category category, final String action, final String effectiveUser, TransportRequest request) {
        
        //skip cluster:monitor, index:monitor, internal:*
        //check transport audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers
        
        return true;
    }
    
    private boolean checkFilter(final Category category, final String effectiveUser, RestRequest request) {
        //check rest audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers
        return true;
    }

    /*private boolean checkActionAndCategory0(final String action, final String effectiveUser, String requestType, final AuditMessage msg) {
        
        //filter upfront
        
        if(action != null 
                && 
                ( action.startsWith("internal:")
                  //|| action.contains("]") //shard level actions
                  || action.startsWith("cluster:monitor")
                  || action.startsWith("indices:monitor")
                )
                && msg.getCategory() != Category.MISSING_PRIVILEGES
                && msg.getCategory() != Category.FAILED_LOGIN
                && msg.getCategory() != Category.SG_INDEX_ATTEMPT) {
            
        
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {}", msg.toPrettyString());
            }
        
            return false;
        }

        if (ignoreAuditUsers.length > 0 && WildcardMatcher.matchAny(ignoreAuditUsers, msg.getEffectiveUser())) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {} because user {} is ignored", msg.toPrettyString(), msg.getEffectiveUser());
            }
            
            return false;
        }
        
        if (ignoreAuditRequests.length > 0 && WildcardMatcher.matchAny(ignoreAuditRequests, msg.getRequestType())) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message {} because request {} is ignored", msg.toPrettyString(), msg.getRequestType());
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
    }*/
    
    protected abstract void save(final AuditMessage msg);
}
