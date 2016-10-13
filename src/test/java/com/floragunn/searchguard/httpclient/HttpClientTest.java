/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 */

package com.floragunn.searchguard.httpclient;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.auditlog.impl.AbstractUnitTest;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class HttpClientTest extends AbstractUnitTest {

    @Test
    public void testPlainConnection() throws Exception {
        
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.transport.enabled", false)
                .put("searchguard.ssl.http.enabled", false)
                //.put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                //.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, false)
                //.put("searchguard.ssl.http.enforce_clientauth", true)
                //.put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                //.put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                //.put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();

        startES(settings);

        try(final HttpClient httpClient = HttpClient.builder(httpHost+":"+httpPort).build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", httpHost+":"+httpPort)
                .enableSsl(getAbsoluteFilePathFromClassPath("truststore.jks"),"changeit", false).build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", httpHost+":"+httpPort).build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
    
    @Test
    public void testSslConnection() throws Exception {
        
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.transport.enabled", false)
                .put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();

        startES(settings);

        try(final HttpClient httpClient = HttpClient.builder(httpHost+":"+httpPort)
                .enableSsl(getAbsoluteFilePathFromClassPath("truststore.jks"),"changeit", false).build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder(httpHost+":"+httpPort).build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
    
    @Test
    public void testSslConnectionPKIAuth() throws Exception {
        
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.transport.enabled", false)
                .put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put("searchguard.ssl.http.clientauth_mode", "REQUIRE")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();

        startES(settings);

        try(final HttpClient httpClient = HttpClient.builder(httpHost+":"+httpPort)
                .enableSsl(getAbsoluteFilePathFromClassPath("truststore.jks"),"changeit", false)
                .setPkiCredentials(getAbsoluteFilePathFromClassPath("node-0-keystore.jks"), "changeit")
                .build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
}
