package com.floragunn.searchguard.auditlog;

import java.util.Collections;
import java.util.Map.Entry;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.rest.RestRequest;

public class MockRestRequest extends RestRequest {

    public MockRestRequest() {
        super("");
    }

    @Override
    public Method method() {
        return Method.GET;
    }

    @Override
    public String uri() {
        return "";
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
        return null;
    }

    @Override
    public Iterable<Entry<String, String>> headers() {
        return Collections.emptyList();
    }
}