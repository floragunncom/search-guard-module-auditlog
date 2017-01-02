/*
 * Copyright 2016 by floragunn GmbH - All rights reserved
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

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.dlic.auditlog.TestAuditlogImpl;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class AuditlogTest {

    @Test
    public void testClusterHealthRequest() {
        Settings settings = Settings.settingsBuilder()
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", 0)
                .build();
        AbstractAuditLog al = new AuditLogImpl(settings, null, null, null);
        TestAuditlogImpl.clear();
        al.logAuthenticatedRequest(new ClusterHealthRequest(), "indices:data/read/search");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
    
    @Test
    public void testSearchRequest() {
        
        SearchRequest sr = new SearchRequest();
        User user = new User("John Doe");
        sr.putInContext(ConfigConstants.SG_USER, user);
        sr.putInContext(ConfigConstants.SG_REMOTE_ADDRESS, "8.8.8.8");
        sr.putInContext(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE");
        sr.putHeader("myheader", "hval");
        sr.indices("index1","logstash*");
        sr.types("mytype","logs");
        sr.source("{\"query\": false}");
        
        Settings settings = Settings.settingsBuilder()
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", 0)
                .build();
        AbstractAuditLog al = new AuditLogImpl(settings, null, null, null);
        TestAuditlogImpl.clear();
        al.logAuthenticatedRequest(sr, "indices:data/read/search");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
}
