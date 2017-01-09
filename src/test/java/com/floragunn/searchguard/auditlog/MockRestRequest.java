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