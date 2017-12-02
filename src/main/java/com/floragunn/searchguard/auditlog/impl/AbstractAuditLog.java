/*
 * Copyright 2016-2017 by floragunn GmbH - All rights reserved
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

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
import com.floragunn.searchguard.support.Base64Helper;
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
    protected final boolean restAuditingEnabled;
    protected final boolean transportAuditingEnabled;
    private final List<String> disabledCategories;

    protected AbstractAuditLog(Settings settings, final ThreadPool threadPool, final IndexNameExpressionResolver resolver, final ClusterService clusterService) {
        super();
        this.threadPool = threadPool;
                
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        
        disabledCategories = Arrays.stream(settings.getAsArray(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_DISABLED_CATEGORIES, new String[]{}))
                .map(c->c.toUpperCase()).collect(Collectors.toList());
        withRequestDetails = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_REQUEST_DETAILS, false);
        resolveBulkRequests = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUDIT_RESOLVE_BULK_REQUESTS, false);
        
        restAuditingEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_REST, true);
        transportAuditingEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_TRANSPORT, false);
        
        ignoreAuditUsers = settings.getAsArray(ConfigConstants.SEARCHGUARD_AUDIT_IGNORE_USERS, new String[]{});
        if (ignoreAuditUsers.length > 0) {
            log.info("Configured Users to ignore: {}", Arrays.toString(ignoreAuditUsers));
        }
        
        ignoreAuditRequests = settings.getAsArray(ConfigConstants.SEARCHGUARD_AUDIT_IGNORE_REQUESTS, new String[]{});
        if (ignoreAuditUsers.length > 0) {
            log.info("Configured Requests to ignore: {}", Arrays.toString(ignoreAuditRequests));
        }
        
        // check if some categories are invalid
        for (String event : disabledCategories) {
        	try {
        		AuditMessage.Category.valueOf(event.toUpperCase());
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
    public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
        if(!checkFilter(Category.MISSING_PRIVILEGES, effectiveUser, request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.MISSING_PRIVILEGES, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(withRequestDetails && request.hasContentOrSourceParam()) {
           msg.addBody(request.contentOrSourceParam());
        }
        msg.addPath(request.path());
        msg.addEffectiveUser(effectiveUser);
        msg.addRestHeaders(request.getHeaders());
        msg.addRestParams(request.params());
        save(msg);
    }

    @Override
    public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
        final String action = null;
        
        if(!checkFilter(Category.MISSING_PRIVILEGES, privilege, getUser(), request)) {
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
        
        if(!checkFilter(Category.GRANTED_PRIVILEGES, privilege, getUser(), request)) {
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
        
        if(!checkFilter(Category.BAD_HEADERS, action, getUser(), request)) {
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
        
        if(!checkFilter(Category.BAD_HEADERS, getUser(), request)) {
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
        
        if(!checkFilter(Category.SG_INDEX_ATTEMPT, action, getUser(), request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.SG_INDEX_ATTEMPT, getOrigin(), action, null, getUser(), false, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, null);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(TransportRequest request, Throwable t, String action, Task task) { 
        
        if(!checkFilter(Category.SSL_EXCEPTION, action, getUser(), request)) {
            return;
        }
        
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(Category.SSL_EXCEPTION, getOrigin(), action, null, getUser(), false, null, remoteAddress, request, 
                getThreadContextHeaders(), task, resolver, clusterService, settings, withRequestDetails, resolveBulkRequests, t);
        
        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(RestRequest request, Throwable t) {
        
        if(!checkFilter(Category.SSL_EXCEPTION, getUser(), request)) {
            return;
        }
        
        AuditMessage msg = new AuditMessage(Category.SSL_EXCEPTION, clusterService, getOrigin());
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        if(request != null && withRequestDetails && request.hasContentOrSourceParam()) {
            msg.addBody(request.contentOrSourceParam());
        }
        
        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders());
            msg.addRestParams(request.params());
        }
        msg.addException(t);
        msg.addEffectiveUser(getUser());
        save(msg);
    }

    private Origin getOrigin() {
        String origin = (String) threadPool.getThreadContext().getTransient(ConfigConstants.SG_ORIGIN);
        
        if(origin == null && threadPool.getThreadContext().getHeader(ConfigConstants.SG_ORIGIN_HEADER) != null) {
            origin = (String) threadPool.getThreadContext().getHeader(ConfigConstants.SG_ORIGIN_HEADER);
        }
        
        return origin == null?null:Origin.valueOf(origin);
    }
    
    private TransportAddress getRemoteAddress() {
        TransportAddress address = threadPool.getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        if(address == null && threadPool.getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER) != null) {
            address = new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER)));
        }
        return address;
    }
    
    private String getUser() {
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.SG_USER);
        if(user == null && threadPool.getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER) != null) {
            user = (User) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER));
        }
        return user==null?null:user.getName();
    }
    
    private Map<String, String> getThreadContextHeaders() {
        return threadPool.getThreadContext().getHeaders();
    }
    
    private boolean checkFilter(final Category category, final String action, final String effectiveUser, TransportRequest request) {
        
        if(log.isTraceEnabled()) {
            log.trace("Check category:{}, action:{}, effectiveUser:{}, request:{}", category, action, effectiveUser, request==null?null:request.getClass().getSimpleName());
        }
        
        
        if(!transportAuditingEnabled) {
            //ignore for certain categories
            if(category != Category.FAILED_LOGIN 
                    && category != Category.MISSING_PRIVILEGES 
                    && category != Category.SG_INDEX_ATTEMPT) {
                
                return false;
            }
            
        }
        
        //skip internals
        if(action != null 
                && 
                ( action.startsWith("internal:")
                  || action.startsWith("cluster:monitor")
                  || action.startsWith("indices:monitor")
                )
                ) {
            
        
            //if(log.isTraceEnabled()) {
            //    log.trace("Skipped audit log message due to category ({}) or action ({}) does not match", category, action);
            //}
        
            return false;
        }
        
        if (ignoreAuditUsers.length > 0 && WildcardMatcher.matchAny(ignoreAuditUsers, effectiveUser)) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }
            
            return false;
        }
        
        if (request != null && ignoreAuditRequests.length > 0 
                && (WildcardMatcher.matchAny(ignoreAuditRequests, action) || WildcardMatcher.matchAny(ignoreAuditRequests, request.getClass().getSimpleName()))) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because request {} is ignored", action+"#"+request.getClass().getSimpleName());
            }
            
            return false;
        }
        
        if (!disabledCategories.contains(category.toString())) {
            return true;        
        } else {
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because category {} not enabled", category);
            }
            return false;
        }
        
        
        //skip cluster:monitor, index:monitor, internal:*
        //check transport audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers

    }
    
    private boolean checkFilter(final Category category, final String effectiveUser, RestRequest request) {
        
        if(log.isTraceEnabled()) {
            log.trace("Check for REST category:{}, effectiveUser:{}, request:{}", category, effectiveUser, request==null?null:request.path());
        }
        
        if(!restAuditingEnabled) {
            //ignore for certain categories
            if(category != Category.FAILED_LOGIN 
                    && category != Category.MISSING_PRIVILEGES 
                    && category != Category.SG_INDEX_ATTEMPT) {
                
                return false;
            }
            
        }
        
        if (ignoreAuditUsers.length > 0 && WildcardMatcher.matchAny(ignoreAuditUsers, effectiveUser)) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }
            
            return false;
        }
        
        if (request != null && ignoreAuditRequests.length > 0 
                && (WildcardMatcher.matchAny(ignoreAuditRequests, request.path()))) {
            
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because request {} is ignored", request.path());
            }
            
            return false;
        }
        
        if (!disabledCategories.contains(category.toString())) {
            return true;        
        } else {
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because category {} not enabled", category);
            }
            return false;
        }
        
        
        //check rest audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers
    }
    
    protected abstract void save(final AuditMessage msg);
}
