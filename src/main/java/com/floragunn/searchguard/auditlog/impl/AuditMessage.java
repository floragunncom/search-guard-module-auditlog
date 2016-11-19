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
import java.util.Map.Entry;

import org.apache.http.client.utils.URIBuilder;
import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

class AuditMessage {

	final Map<AuditMessageKey, Object> auditInfo = new HashMap<AuditMessageKey, Object>();
	final Category category;

	public AuditMessage(final Category category, final Object reason, final Object details, final ContextAndHeaderHolder request) {
		this.category = category;

		final User user = request.getFromContext(ConfigConstants.SG_USER);
		final String requestUser = user == null ? null : user.getName();

		auditInfo.put(AuditMessageKey.CATEGORY, category.toString());
		auditInfo.put(AuditMessageKey.REQUEST_USER, requestUser);
		auditInfo.put(AuditMessageKey.REASON, String.valueOf(reason));
		auditInfo.put(AuditMessageKey.DETAILS, String.valueOf(details));
		auditInfo.put(AuditMessageKey.DATE, new Date().toString());
		auditInfo.put(AuditMessageKey.REQUEST_CONTEXT, String.valueOf(request.getContext()));
		auditInfo.put(AuditMessageKey.REQUEST_HEADERS, String.valueOf(request.getHeaders()));
		auditInfo.put(AuditMessageKey.REQUEST_CLASS, request.getClass().toString());
		auditInfo.put(AuditMessageKey.REMOTE_ADDRESS, request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS));
		auditInfo.put(AuditMessageKey.PRINCIPAL, request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL));
	}

	AuditMessage(final Category category, final Object reason, final Object details, final TransportRequest request) {
		this(category, reason, details, (ContextAndHeaderHolder) request);
	}

	AuditMessage(final Category category, final Object reason, final Object details, final RestRequest request) {
		this(category, reason, details, (ContextAndHeaderHolder) request);
	}

	public Map<AuditMessageKey, Object> getAsMap() {
		return Collections.unmodifiableMap(this.auditInfo);
	}

	public Map<String, Object> getAsMapWithStringKeys() {
		Map<String, Object> stringMap = new HashMap<>();
		for (Entry<AuditMessageKey, Object> entry : this.auditInfo.entrySet()) {
			stringMap.put(entry.getKey().name, entry.getValue());
		}
		return stringMap;
	}

	public Category getCategory() {
		return category;
	}

	@Override
	public String toString() {
		try {
			return JsonXContent.contentBuilder().map(getAsMapWithStringKeys()).string();
		} catch (final IOException e) {
			return e.toString();
		}
	}

	public String toText() {
		StringBuilder builder = new StringBuilder();
		AuditMessageKey[] allKeys = AuditMessageKey.values();
		for (AuditMessageKey auditMessageKey : allKeys) {
			addIfNonEmpty(builder, auditMessageKey.getName(), String.valueOf(auditInfo.get(auditMessageKey)));
		}
		return builder.toString();
	}

	public String toJson() {
		return this.toString();
	}

	public String toUrlParameters() {
		URIBuilder builder = new URIBuilder();
		AuditMessageKey[] allKeys = AuditMessageKey.values();
		for (AuditMessageKey auditMessageKey : allKeys) {
			builder.addParameter(auditMessageKey.getName(), String.valueOf(auditInfo.get(auditMessageKey)));
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

	enum Category {
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

	enum AuditMessageKey {

		DATE("Date"),
		CATEGORY("Category"),
		REQUEST_USER("Request User"),
		REMOTE_ADDRESS("Remote Address"),
		REASON("Reason"),
		DETAILS("Details"),
		REQUEST_CLASS("Request class"),
		REQUEST_CONTEXT("Context"),
		REQUEST_HEADERS("Headers"),
		PRINCIPAL("TLS Principal");

		private String name;

		private AuditMessageKey(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}
	}
}
