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
import java.util.Map;

import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

class AuditMessage {
    final Map<String, Object> auditInfo = new HashMap<String, Object>();

    enum Category {
        BAD_HEADERS, FAILED_LOGIN, MISSING_PRIVILEGES, SG_INDEX_ATTEMPT, SSL_EXCEPTION, AUTHENTICATED
    }

    public AuditMessage(final Category category, final Object reason, final Object details, final ContextAndHeaderHolder request) {
        final User user = request.getFromContext(ConfigConstants.SG_USER);
        final String requestUser = user == null ? null : user.getName();

        auditInfo.put("audit_category", category.toString());
        auditInfo.put("audit_request_user", requestUser);
        auditInfo.put("audit_reason", String.valueOf(reason));
        auditInfo.put("audit_details", String.valueOf(details));
        auditInfo.put("audit_date", new Date().toString());
        auditInfo.put("audit_request_context", String.valueOf(request.getContext()));
        auditInfo.put("audit_request_headers", String.valueOf(request.getHeaders()));
        auditInfo.put("audit_request_class", request.getClass().toString());
        auditInfo.put("audit_remote_address", request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS));
        auditInfo.put("audit_principal", request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL));
    }

    AuditMessage(final Category category, final Object reason, final Object details, final TransportRequest request) {
        this(category, reason, details, (ContextAndHeaderHolder) request);
    }

    AuditMessage(final Category category, final Object reason, final Object details, final RestRequest request) {
        this(category, reason, details, (ContextAndHeaderHolder) request);
    }

    public Map<String, Object> getAsMap() {
        return Collections.unmodifiableMap(this.auditInfo);
    }

    @Override
    public String toString() {
        try {
            return JsonXContent.contentBuilder().map(this.auditInfo).string();
        } catch (final IOException e) {
            return e.toString();
        }
    }
}
