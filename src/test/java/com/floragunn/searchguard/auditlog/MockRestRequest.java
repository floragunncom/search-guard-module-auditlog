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

package com.floragunn.searchguard.auditlog;

import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.rest.RestRequest;

public class MockRestRequest extends RestRequest {

    private final Map<String, String> headers;

    private final Map<String, String> params;

    public MockRestRequest() {
        this(new HashMap<String, String>(), new HashMap<String, Object>());
    }

    public MockRestRequest(Map<String, String> headers, Map<String, Object> context) {
        this.headers = headers;
        for (Map.Entry<String, Object> entry : context.entrySet()) {
            putInContext(entry.getKey(), entry.getValue());
        }
        this.params = new HashMap<>();
    }

    @Override
    public Method method() {
        return Method.GET;
    }

    @Override
    public String uri() {
        return "/";
    }

    @Override
    public String rawPath() {
        return "/";
    }

    @Override
    public boolean hasContent() {
        return false;
    }

    @Override
    public BytesReference content() {
        return null;
    }

    @Override
    public String header(String name) {
        return headers.get(name);
    }

    @Override
    public Iterable<Map.Entry<String, String>> headers() {
        return headers.entrySet();
    }

    @Override
    public boolean hasParam(String key) {
        return params.containsKey(key);
    }

    @Override
    public String param(String key) {
        return params.get(key);
    }

    @Override
    public String param(String key, String defaultValue) {
        String value = params.get(key);
        if (value == null) {
            return defaultValue;
        }
        return value;
    }

    @Override
    public Map<String, String> params() {
        return params;
    }
}