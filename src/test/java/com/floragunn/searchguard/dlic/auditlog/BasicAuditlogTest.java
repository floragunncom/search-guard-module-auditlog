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

package com.floragunn.searchguard.dlic.auditlog;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class BasicAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.SEARCHGUARD_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.SEARCHGUARD_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", 0)
                .build();
        
        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();
   
        testMsearch();
        TestAuditlogImpl.clear();
        
        testBulkAuth();
        TestAuditlogImpl.clear();
        
        testBulkNonAuth();
        TestAuditlogImpl.clear();
        
        testUpdateSettings();
        TestAuditlogImpl.clear();
    }
    
    @Test
    public void testNonAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("searchguard.audit.type", TestAuditlogImpl.class.getName())
                .put("searchguard.audit.enable_request_details", true)
                .put("searchguard.audit.threadpool.size", -1)
                .putArray("searchguard.audit.config.disabled_categories", "AUTHENTICATED")
                .build();
        
        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();
        
        testJustAuthenticated();
        TestAuditlogImpl.clear();
        testBadHeader();
        TestAuditlogImpl.clear();
        testMissingPriv();
        TestAuditlogImpl.clear();
        testSgIndexAttempt();
        TestAuditlogImpl.clear();
        testUnauthenticated();
        TestAuditlogImpl.clear();
        testUnknownAuthorization();
        TestAuditlogImpl.clear();
        testWrongUser();
        TestAuditlogImpl.clear();

    }
    
    public void testWrongUser() throws Exception {
      
        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("wronguser", "admin"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(500);
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("wronguser"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("utc_timestamp"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
   

    public void testUnknownAuthorization() throws Exception {
       
        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("unknown", "unknown"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("Basic dW5rbm93bjp1bmtub3du"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("utc_timestamp"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
    

    public void testUnauthenticated() throws Exception {
     
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        System.out.println(response.getBody());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("/_search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("utc_timestamp"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
    

    public void testJustAuthenticated() throws Exception {
        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
    }
    

    public void testSgIndexAttempt() throws Exception {
       
        HttpResponse response = rh.executePutRequest("searchguard/config/0", "{}", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("SG_INDEX_ATTEMPT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("admin"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("utc_timestamp"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
    }
    

    public void testBadHeader() throws Exception {
      
        HttpResponse response = rh.executeGetRequest("", new BasicHeader("_sg_bad", "bad"), encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertFalse(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("BAD_HEADERS"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("_sg_bad"));
        Assert.assertEquals(TestAuditlogImpl.sb.toString(), 1, TestAuditlogImpl.messages.size());
    }
    
    
    public void testMissingPriv() throws Exception {

        HttpResponse response = rh.executeGetRequest("sf/_search", encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("worf"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"sf\""));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("utc_timestamp"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }
    
	public void testMsearch() throws Exception {
        
        String msearch = 
                "{\"index\":\"sf\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":0,\"query\":{\"match_all\":{}}}"+System.lineSeparator()+
                "{\"index\":\"sf\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":0,\"query\":{\"match_all\":{}}}"+System.lineSeparator();           
            
        System.out.println("##### msaerch");
        HttpResponse response = rh.executePostRequest("_msearch?pretty", msearch, encodeBasicHeader("admin", "admin"));        
        Assert.assertEquals(response.getStatusReason(), HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("indices:data/read/msearch"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("match_all"));
        Assert.assertEquals(TestAuditlogImpl.sb.toString(), 4, TestAuditlogImpl.messages.size());
	}
	
	
    public void testBulkAuth() throws Exception {

        System.out.println("#### testBulkAuth");
        String bulkBody = 
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"worf\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                
                "{ \"update\" : {\"_id\" : \"1\", \"_type\" : \"type1\", \"_index\" : \"test\"} }"+System.lineSeparator()+
                "{ \"doc\" : {\"field\" : \"valuex\"} }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"create\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value3x\" }"+System.lineSeparator();
                

        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("admin", "admin"));
        System.out.println(response.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());  
        Assert.assertTrue(response.getBody().contains("\"errors\":false"));
        Assert.assertTrue(response.getBody().contains("\"status\":201"));                   
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:admin/create"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/write/bulk"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("IndexRequest"));
        System.out.println(TestAuditlogImpl.sb.toString());
        //may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 17); 
    }
    
    public void testBulkNonAuth() throws Exception {

        String bulkBody = 
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"worf\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                
                "{ \"update\" : {\"_id\" : \"1\", \"_type\" : \"type1\", \"_index\" : \"test\"} }"+System.lineSeparator()+
                "{ \"doc\" : {\"field\" : \"valuex\"} }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"create\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value3x\" }"+System.lineSeparator();

        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("worf", "worf"));
        System.out.println(response.getBody());

        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"errors\":true"));
        Assert.assertTrue(response.getBody().contains("\"status\":200")); 
        Assert.assertTrue(response.getBody().contains("\"status\":403"));   
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/write/bulk[s]"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("IndexRequest"));
        //may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 7);
    }
	
    public void testUpdateSettings() throws Exception {
        
        String json = 
        "{"+
            "\"persistent\" : {"+
                "\"discovery.zen.minimum_master_nodes\" : 1"+
            "},"+
            "\"transient\" : {"+
                "\"discovery.zen.minimum_master_nodes\" : 1"+
             "}"+
        "}";

        HttpResponse response = rh.executePutRequest("_cluster/settings", json, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("cluster:admin/settings/update"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("discovery.zen.minimum_master_nodes"));
        //may vary because we log may hit master directly or not
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 1);
    }
    
    @Test
    public void testIndexPattern() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("searchguard.audit.type", "internal_elasticsearch")
                .put("searchguard.audit.enable_request_details", false)
                .put("searchguard.audit.threadpool.size", 10) //must be greater 0
                .put("searchguard.audit.config.index", "'auditlog-'YYYY.MM.dd.ss")
                .build();
        
        setup(additionalSettings);
        setupStarfleetIndex();

        final boolean sendHTTPClientCertificate = rh.sendHTTPClientCertificate;
        final String keystore = rh.keystore;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        HttpResponse res = rh.executeGetRequest("_cat/indices", new Header[0]);
        rh.sendHTTPClientCertificate = sendHTTPClientCertificate;
        rh.keystore = keystore;

        Assert.assertTrue(res.getBody().contains("auditlog-20"));
    }
}
