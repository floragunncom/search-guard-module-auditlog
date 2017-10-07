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

package com.floragunn.searchguard.httpclient;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;

import com.google.common.collect.Lists;

public class HttpClient implements Closeable {

    public static class HttpClientBuilder {

        private File trustStore;
        private String truststorePassword;
        private String basicCredentials;
        private File keystore;
        private String keystorePassword;
        private boolean verifyHostnames;
        private final String[] servers;
        private boolean ssl;

        private HttpClientBuilder(final String... servers) {
            super();
            this.servers = Objects.requireNonNull(servers);
            if (this.servers.length == 0) {
                throw new IllegalArgumentException();
            }
        }

        public HttpClientBuilder enableSsl(final File trustStore, final String truststorePassword, final boolean verifyHostnames) {
            this.ssl = true;
            this.trustStore = Objects.requireNonNull(trustStore);
            this.truststorePassword = truststorePassword;
            this.verifyHostnames = verifyHostnames;
            return this;
        }

        public HttpClientBuilder setBasicCredentials(final String username, final String password) {
            basicCredentials = encodeBasicHeader(Objects.requireNonNull(username), Objects.requireNonNull(password));
            return this;
        }

        public HttpClientBuilder setPkiCredentials(final File keystore, final String keystorePassword) {
            this.keystore = Objects.requireNonNull(keystore);
            this.keystorePassword = keystorePassword;
            return this;
        }

        public HttpClient build() throws Exception {
            return new HttpClient(trustStore, truststorePassword, basicCredentials, keystore, keystorePassword, verifyHostnames, ssl,
                    servers);
        }
        
        private static String encodeBasicHeader(final String username, final String password) {
            return new String(DatatypeConverter.printBase64Binary((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
        }

    }

    public static HttpClientBuilder builder(final String... servers) {
        return new HttpClientBuilder(servers);
    }

    private final File trustStore;
    private final String truststorePassword;
    private final Logger log = LogManager.getLogger(this.getClass());
    private RestHighLevelClient rclient;
    private String basicCredentials;
    private File keystore;
    private String keystorePassword;
    private boolean verifyHostnames;
    private boolean ssl;

    private HttpClient(final File trustStore, final String truststorePassword, final String basicCredentials, final File keystore,
            final String keystorePassword, final boolean verifyHostnames, final boolean ssl, final String... servers)
            throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException,
            FileNotFoundException, IOException {
        super();
        this.trustStore = trustStore;
        this.truststorePassword = truststorePassword;
        this.basicCredentials = basicCredentials;
        this.keystore = keystore;
        this.keystorePassword = keystorePassword;
        this.verifyHostnames = verifyHostnames;
        this.ssl = ssl;

        HttpHost[] hosts = Arrays.stream(servers)
                .map(s->s.split(":"))
                .map(s->new HttpHost(s[0], Integer.parseInt(s[1]),ssl?"https":"http"))
                .collect(Collectors.toList()).toArray(new HttpHost[0]);
                
        
        RestClientBuilder builder = RestClient.builder(hosts);
        //builder.setMaxRetryTimeoutMillis(10000);
        builder.setFailureListener(new RestClient.FailureListener() {
            @Override
            public void onFailure(HttpHost host) {
                
            }
        });
        /*builder.setRequestConfigCallback(new RestClientBuilder.RequestConfigCallback() {
            @Override
            public RequestConfig.Builder customizeRequestConfig(RequestConfig.Builder requestConfigBuilder) {
                requestConfigBuilder.setAuthenticationEnabled(true);
                return requestConfigBuilder.setSocketTimeout(10000); 
            }
        });*/
        builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                try {
                    return asyncClientBuilder(httpClientBuilder);
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        });
        
        rclient = new RestHighLevelClient(builder);
    }

    public boolean index(final String content, final String index, final String type, final boolean refresh) {

            try {
                final IndexResponse response = rclient.index(new IndexRequest(index, type)
                              .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                              .source(content, XContentType.JSON));
                
                return response.getShardInfo().getSuccessful() > 0 && response.getShardInfo().getFailed() == 0;
                
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return false;
            }
    }

    private final HttpAsyncClientBuilder asyncClientBuilder(HttpAsyncClientBuilder httpClientBuilder) throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
    FileNotFoundException, IOException, UnrecoverableKeyException, KeyManagementException {

        // basic auth
        // pki auth

        if (ssl) {

            final SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if (log.isTraceEnabled()) {
                log.trace("Configure HTTP client with SSL");
            }

            if (trustStore != null) {
                final KeyStore myTrustStore = KeyStore.getInstance(trustStore.getName().endsWith("jks") ? "JKS" : "PKCS12");
                myTrustStore.load(new FileInputStream(trustStore),
                        truststorePassword == null || truststorePassword.isEmpty() ? null : truststorePassword.toCharArray());
                sslContextBuilder.loadTrustMaterial(myTrustStore, null);
            }

            if (keystore != null) {
                final KeyStore keyStore = KeyStore.getInstance(keystore.getName().endsWith("jks") ? "JKS" : "PKCS12");
                keyStore.load(new FileInputStream(keystore), keystorePassword == null || keystorePassword.isEmpty() ? null
                        : keystorePassword.toCharArray());
                sslContextBuilder.loadKeyMaterial(keyStore, keystorePassword == null || keystorePassword.isEmpty() ? null
                        : keystorePassword.toCharArray());
            }

            final HostnameVerifier hnv = verifyHostnames?new DefaultHostnameVerifier():NoopHostnameVerifier.INSTANCE;
            String[] supportedProtocols = new String[] { "TLSv1.1", "TLSv1.2" };
            String[] supportedCipherSuites = null;
            
            final SSLContext sslContext = sslContextBuilder.build();
            httpClientBuilder.setSSLStrategy(new SSLIOSessionStrategy(
                    sslContext,
                    supportedProtocols,
                    supportedCipherSuites,
                    hnv
                    ));
        }

        if (basicCredentials != null) {
            httpClientBuilder.setDefaultHeaders(Lists.newArrayList(new BasicHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicCredentials)));
        }
        
        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;
        
        RequestConfig config = RequestConfig.custom()
          .setConnectTimeout(timeout * 1000)
          .setConnectionRequestTimeout(timeout * 1000)
          .setSocketTimeout(timeout * 1000).build();
        
        httpClientBuilder.setDefaultRequestConfig(config);
        
        return httpClientBuilder;
        
    }

    @Override
    public void close() throws IOException {
        if (rclient != null) {
            rclient.close();
        }
    }
}
