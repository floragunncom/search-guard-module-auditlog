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
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.auditlog.support.Cycle;
import com.floragunn.searchguard.support.Base64Helper;
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
            basicCredentials = Base64Helper.encodeBasicHeader(Objects.requireNonNull(username), Objects.requireNonNull(password));
            return this;
        }

        public HttpClientBuilder setPkiCredentials(final File keystore, final String keystorePassword) {
            this.keystore = Objects.requireNonNull(keystore);
            this.keystorePassword = keystorePassword;
            return this;
        }

        /*public HttpClientBuilder setKerberosCredentials(final Path keytab) {
           this.keytab = keytab;
        }*/

        public HttpClient build() throws Exception {
            return new HttpClient(trustStore, truststorePassword, basicCredentials, keystore, keystorePassword, verifyHostnames, ssl,
                    servers);
        }

    }

    public static HttpClientBuilder builder(final String... servers) {
        return new HttpClientBuilder(servers);
    }

    private final List<String> servers = new ArrayList<String>(); // server:port
    private final File trustStore;
    private final String truststorePassword;
    private final ESLogger log = Loggers.getLogger(this.getClass());
    private CloseableHttpClient client;
    private String basicCredentials;
    // private Path keytab;
    private File keystore;
    private String keystorePassword;
    private boolean verifyHostnames;
    private Cycle<String> cservers;
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

        this.servers.addAll(Arrays.asList(servers));
        this.cservers = new Cycle<String>(servers);
        this.client = createHTTPClient();
    }

    public boolean index(final String content, final String index, final String type, final boolean refresh) {

        for (int i = 0; i < servers.size(); i++) {

            final String server = cservers.next();

            final HttpPost indexRequest = new HttpPost("http" + (ssl ? "s" : "") + "://" + server + "/" + index + "/" + type
                    + (refresh ? "/?refresh=true" : "/"));

            final StringEntity entity = new StringEntity(content, ContentType.APPLICATION_JSON);
            indexRequest.setEntity(entity);

            CloseableHttpResponse response = null;
            XContentParser parser = null;
            try {
                response = client.execute(indexRequest);

                if (response != null && response.getStatusLine() != null && response.getStatusLine().getStatusCode() < 400) {

                    // TODO check successfull at least 1
                    HttpEntity responseEntity = response.getEntity();

                    if (responseEntity != null) {

                        final InputStream contentStream = responseEntity.getContent();

                        if (contentStream != null) {
                            parser = XContentFactory.xContent(XContentType.JSON).createParser(contentStream);
                            final Map<String, Object> map = parser.map();

                            if (map != null && map.containsKey("_shards")) {
                                final Map<String, Object> shards = (Map<String, Object>) map.get("_shards");

                                if (shards != null && shards.containsKey("successful")) {
                                    final Integer successfulShards = (Integer) shards.get("successful");
                                    return successfulShards != null && successfulShards.intValue() > 0;
                                }

                            }
                        }
                    }
                }
                
            } catch (final Exception e) {
                log.debug(e.toString(), e);
            } finally {
                if (response != null) {
                    try {
                        response.close();
                    } catch (final Exception e) {
                        // ignore
                    }
                }

                if (parser != null) {
                    parser.close();
                }
            }
        }

        return false;
    }

    private final CloseableHttpClient createHTTPClient() throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
    FileNotFoundException, IOException, UnrecoverableKeyException, KeyManagementException {

        // basic auth
        // pki auth
        // kerberos auth

        final org.apache.http.impl.client.HttpClientBuilder hcb = HttpClients.custom();

        if (ssl) {

            final SSLContextBuilder sslContextbBuilder = SSLContexts.custom().useTLS();

            if (log.isTraceEnabled()) {
                log.trace("Configure HTTP client with SSL");
            }

            if (trustStore != null) {
                final KeyStore myTrustStore = KeyStore.getInstance(trustStore.getName().endsWith("jks") ? "JKS" : "PKCS12");
                myTrustStore.load(new FileInputStream(trustStore),
                        truststorePassword == null || truststorePassword.isEmpty() ? null : truststorePassword.toCharArray());
                sslContextbBuilder.loadTrustMaterial(myTrustStore);
            }

            if (keystore != null) {
                final KeyStore keyStore = KeyStore.getInstance(keystore.getName().endsWith("jks") ? "JKS" : "PKCS12");
                keyStore.load(new FileInputStream(keystore), keystorePassword == null || keystorePassword.isEmpty() ? null
                        : keystorePassword.toCharArray());
                sslContextbBuilder.loadKeyMaterial(keyStore, keystorePassword == null || keystorePassword.isEmpty() ? null
                        : keystorePassword.toCharArray());
            }

            final SSLContext sslContext = sslContextbBuilder.build();
            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, new String[] { "TLSv1.1", "TLSv1.2" },
                    null, verifyHostnames ? SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER
                            : SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            hcb.setSSLSocketFactory(sslsf);
        }

        /*if (keytab != null) {

            //System.setProperty("java.security.auth.login.config", "login.conf");
            //System.setProperty("java.security.krb5.conf", "krb5.conf");


            final CredentialsProvider credsProvider = new BasicCredentialsProvider();
            //SPNEGO/Kerberos setup
            log.debug("SPNEGO activated");
            final AuthSchemeProvider nsf = new LoginSPNegoSchemeFactory(true);
            final Credentials jaasCreds = new JaasCredentials();
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.SPNEGO), jaasCreds);
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.NTLM), new NTCredentials("Guest", "Guest", "Guest",
                    "Guest"));
            final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
                    .register(AuthSchemes.SPNEGO, nsf).register(AuthSchemes.NTLM, new NTLMSchemeFactory()).build();

            hcb.setDefaultAuthSchemeRegistry(authSchemeRegistry);
            hcb.setDefaultCredentialsProvider(credsProvider);
        }*/

        if (basicCredentials != null) {
            hcb.setDefaultHeaders(Lists.newArrayList(new BasicHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicCredentials)));
        }

        return hcb.build();
    }

    @Override
    public void close() throws IOException {
        if (client != null) {
            client.close();
        }
    }

    /*
    private static class JaasCredentials implements Credentials {

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static class LoginSPNegoSchemeFactory implements AuthSchemeFactory, AuthSchemeProvider {

        private final boolean stripPort;

        public LoginSPNegoSchemeFactory(final boolean stripPort) {
            super();
            this.stripPort = stripPort;
        }

        public LoginSPNegoSchemeFactory() {
            this(false);
        }

        public boolean isStripPort() {
            return stripPort;
        }

        public AuthScheme newInstance(final HttpParams params) {
            return new LoginSPNegoScheme(this.stripPort);
        }

        public AuthScheme create(final HttpContext context) {
            return new LoginSPNegoScheme(this.stripPort);
        }

    }

    private static class LoginSPNegoScheme extends SPNegoScheme {

        private static final Oid _SPNEGO_OID;
        static {

            Oid oid = null;

            try {
                oid = new Oid("1.3.6.1.5.5.2");
            } catch (GSSException e) {

            }


            _SPNEGO_OID = oid;
        }


        private final Subject initiatorSubject;
        private final String acceptorPrincipal;

        public LoginSPNegoScheme() {
            super();
            // TODO Auto-generated constructor stub
        }

        public LoginSPNegoScheme(boolean stripPort) {
            super(stripPort);
            // TODO Auto-generated constructor stub
        }

        @Override
        protected byte[] generateToken(byte[] input, String authServer) throws GSSException {

            byte[] token = input;
            if (token == null) {
                token = new byte[0];
            }
            final GSSManager manager = getManager();
            final GSSName serverName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);
            final GSSContext gssContext = manager.createContext(
                    serverName.canonicalize(_SPNEGO_OID), _SPNEGO_OID, null, GSSContext.DEFAULT_LIFETIME);
            gssContext.requestMutualAuth(true);
            gssContext.requestCredDeleg(true);
            return gssContext.initSecContext(token, 0, token.length);

            //
            final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                @Override
                public GSSCredential run() throws GSSException {
                    return MANAGER.createCredential(null, GSSCredential.DEFAULT_LIFETIME, KrbConstants.SPNEGO, GSSCredential.INITIATE_ONLY);
                }
            };

            final GSSCredential clientcreds = Subject.doAs(initiatorSubject, action);

            final GSSContext context = MANAGER.createContext(MANAGER.createName(acceptorPrincipal, GSSName.NT_USER_NAME, KrbConstants.SPNEGO),
                    KrbConstants.SPNEGO, clientcreds, GSSContext.DEFAULT_LIFETIME);

            //TODO make configurable
            context.requestMutualAuth(true);
            context.requestConf(true);
            context.requestInteg(true);
            context.requestReplayDet(true);
            context.requestSequenceDet(true);
            context.requestCredDeleg(false);

            return context;


        }

    }*/

}
