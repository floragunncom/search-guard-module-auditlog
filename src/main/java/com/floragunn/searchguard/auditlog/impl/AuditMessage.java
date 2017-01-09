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

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.http.client.utils.URIBuilder;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class AuditMessage {

    private static final DateTimeFormatter DEFAULT_FORMAT = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");
    protected final Map<String, Object> auditInfo = new HashMap<String, Object>(50);
    protected final Category category;

    protected AuditMessage(final Category category, final Object reason, final Object details, final ContextAndHeaderHolder request,
	        final boolean withRequestDetails, final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService,
	        final Settings settings) {
		this.category = category;

		final User user = request.getFromContext(ConfigConstants.SG_USER);
		final String requestUser = user == null ? null : user.getName();
		final String currentTime = currentTime();
		
		auditInfo.put(AuditMessageKey.FORMAT_VERSION, 2);
		auditInfo.put(AuditMessageKey.CATEGORY, stringOrNull(category));
		auditInfo.put(AuditMessageKey.REQUEST_USER, requestUser);
		auditInfo.put(AuditMessageKey.REASON, stringOrNull(reason));
		auditInfo.put(AuditMessageKey.DETAILS, stringOrNull(details));
		auditInfo.put(AuditMessageKey.DATE, new Date().toString());
		auditInfo.put(AuditMessageKey.UTC_TIMESTAMP, currentTime);
		
		if(request instanceof RestRequest) {
		    final RestRequest restRequest = (RestRequest) request;
		    auditInfo.put(AuditMessageKey.REST_PATH, restRequest.rawPath());
		    auditInfo.put(AuditMessageKey.REQUEST_HEADERS, stringOrNull(restRequest.headers()));       
		} else {
		    final Set<String> tHeaders = request.getHeaders();
		    final Map<String, String> tHeadersMap = new HashMap<String, String>(tHeaders.size());
		    
		    for (Iterator<String> iterator = tHeaders.iterator(); iterator.hasNext();) {
		        final String key = iterator.next();
                tHeadersMap.put(key,  String.valueOf(request.getHeader(key)));
            }
		    
		    auditInfo.put(AuditMessageKey.REQUEST_HEADERS, stringOrNull(tHeadersMap.entrySet()));       
		}
		
		DiscoveryNode localNode = clusterService == null ? null : clusterService.get().localNode();
		
		auditInfo.put(AuditMessageKey.NODE_ID, localNode == null?null:localNode.id());
		auditInfo.put(AuditMessageKey.NODE_NAME, localNode == null?null:localNode.name());
		auditInfo.put(AuditMessageKey.NODE_HOST, localNode == null?null:localNode.getHostName());
		
		auditInfo.put(AuditMessageKey.REQUEST_CONTEXT, stringOrNull(request.getContext()));
		auditInfo.put(AuditMessageKey.REQUEST_CLASS, request.getClass().toString());
		auditInfo.put(AuditMessageKey.REMOTE_ADDRESS, stringOrNull(request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS)));
		auditInfo.put(AuditMessageKey.PRINCIPAL, stringOrNull(request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL)));
		auditInfo.put(AuditMessageKey.TYPE, (request instanceof RestRequest?"rest":"transport"));
		
		if(withRequestDetails) {
    		try {
                RequestResolver.resolve(request, auditInfo, resolver, clusterService, settings);
            } catch (IOException e) {
                throw ExceptionsHelper.convertToElastic(e);
            }
		}
	}

    protected AuditMessage(final Category category, final Object reason, final Object details, final TransportRequest request,
	        final boolean withRequestDetails, final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService,
	        final Settings settings) {
		this(category, reason, details, (ContextAndHeaderHolder) request, withRequestDetails, resolver, clusterService, settings);
	}

    protected AuditMessage(final Category category, final Object reason, final Object details, final RestRequest request,
	        final boolean withRequestDetails, final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService,
	        final Settings settings) {
		this(category, reason, details, (ContextAndHeaderHolder) request, withRequestDetails, resolver, clusterService, settings);
	}
    
    public Map<String, Object> getAsMap() {
      return Collections.unmodifiableMap(this.auditInfo);
    }

	public Category getCategory() {
		return category;
	}

	@Override
	public String toString() {
		try {
			return JsonXContent.contentBuilder().map(auditInfo).string();
		} catch (final IOException e) {
		    throw ExceptionsHelper.convertToElastic(e);
		}
	}
	
    public String toPrettyString() {
        try {
            return JsonXContent.contentBuilder().prettyPrint().map(auditInfo).string();
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

	public String toText() {
		StringBuilder builder = new StringBuilder();
		for (Entry<String, Object> entry : auditInfo.entrySet()) {
			addIfNonEmpty(builder, entry.getKey(), stringOrNull(entry.getValue()));
		}
		return builder.toString();
	}

	public String toJson() {
		return this.toString();
	}

	public String toUrlParameters() {
		URIBuilder builder = new URIBuilder();
		for (Entry<String, Object> entry : auditInfo.entrySet()) {
			builder.addParameter(entry.getKey(), stringOrNull(entry.getValue()));
		}
		return builder.toString();
	}
	
	private void addIfNonEmpty(StringBuilder builder, String key, String value) {
		if (!Strings.isEmpty(value)) {
			if (builder.length() > 0) {
				builder.append("\n");
			}
			builder.append(key).append(": ").append(value);
		}
	}
	
	protected enum Category {
        BAD_HEADERS,
        FAILED_LOGIN,
        MISSING_PRIVILEGES,
        SG_INDEX_ATTEMPT,
        SSL_EXCEPTION,
        AUTHENTICATED;

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

    }
	
	protected static class AuditMessageKey {
	    
	    public static final String FORMAT_VERSION = "audit_format_version";
	    public static final String DATE = "audit_date";
	    public static final String CATEGORY = "audit_category";
	    public static final String REQUEST_USER = "audit_request_user";
	    public static final String REMOTE_ADDRESS = "audit_remote_address";
	    public static final String REASON = "audit_reason";
	    public static final String DETAILS = "audit_details";
	    public static final String REQUEST_CLASS = "audit_request_class";
	    public static final String REQUEST_CONTEXT = "audit_request_context";
	    public static final String REQUEST_HEADERS = "audit_request_headers";
	    public static final String PRINCIPAL = "audit_principal";
	    public static final String UTC_TIMESTAMP = "audit_utc_timestamp";
	    public static final String TYPE = "audit_request_type";
        
	    public static final String INDICES = "audit_trace_indices";
	    public static final String RESOLVED_INDICES = "audit_trace_resolved_indices";
	    public static final String TYPES = "audit_trace_index_types";
	    public static final String CAUSE = "audit_trace_index_cause";
	    public static final String SOURCE = "audit_trace_source";
	    public static final String ID = "audit_trace_id";
        
	    public static final String NODE_ID = "audit_node_id";
	    public static final String NODE_HOST = "audit_node_host";
	    public static final String NODE_NAME = "audit_node_name";
        
	    public static final String SUBREQUEST_COUNT = "audit_trace_subrequest_count";
        
	    public static final String REST_PATH = "audit_request_path";
	    
	    public static final String INNER_CLASS = "audit_trace_inner_class";
	    
	}

    protected String currentTime() {
        DateTime dt = new DateTime(DateTimeZone.UTC);        
        return DEFAULT_FORMAT.print(dt);
    }
    
    protected String stringOrNull(Object object) {
        if(object == null) {
            return null;            
        }
        
        return String.valueOf(object);
    }

}
