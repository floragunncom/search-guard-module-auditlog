package com.floragunn.searchguard.auditlog.impl;

import com.floragunn.searchguard.dlic.auditlog.TestAuditlogImpl;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Created by martin.stange on 19.04.2017.
 */
public class IgnoreAuditUsersTest {

    static String ignoreUser = "Wesley Crusher";
    String nonIgnoreUser = "Diana Crusher";
    static SearchRequest sr;

    @BeforeClass
    public static void initSearchRequest() {
        sr = new SearchRequest();
        User user = new User(ignoreUser);
        sr.putInContext(ConfigConstants.SG_USER, user);
        sr.putHeader("myheader", "hval");
        sr.indices("index1", "logstash*");
        sr.types("mytype", "logs");
        sr.source("{\"query\": false}");
    }


    @Test
    public void testConfiguredIgnoreUser() {
        Settings settings = Settings.settingsBuilder()
                .put("searchguard.audit.ignore.users", ignoreUser)
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", 0)
                .build();
        AbstractAuditLog al = new AuditLogImpl(settings, null, null, null);
        TestAuditlogImpl.clear();
        al.logAuthenticatedRequest(sr, "indices:data/read/search");
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testNonConfiguredIgnoreUser() {
        Settings settings = Settings.settingsBuilder()
                .put("searchguard.audit.ignore.users", nonIgnoreUser)
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", 0)
                .build();
        AbstractAuditLog al = new AuditLogImpl(settings, null, null, null);
        TestAuditlogImpl.clear();
        al.logAuthenticatedRequest(sr, "indices:data/read/search");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testNonExistingIgnoreUser() {
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