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
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.threadpool.ThreadPool;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.floragunn.searchguard.httpclient.HttpClient;
import com.floragunn.searchguard.httpclient.HttpClient.HttpClientBuilder;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public final class HttpESAuditLog extends AuditLogSink {

	// config in elasticsearch.yml
	private final String index;
	private final String type;
	private final HttpClient client;
	private final String[] servers;
	private DateTimeFormatter indexPattern;
	
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    static final String PKCS12 = "PKCS12";
    static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    public static final String AUDIT_SSL_VERIFY_HOSTNAMES = "verify_hostnames";
    public static final boolean AUDIT_SSL_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final String AUDIT_SSL_ENABLE_SSL = "enable_ssl";
    public static final String AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";
    public static final boolean AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;
    
    public static final String AUDIT_SSL_JKS_CERT_ALIAS = "cert_alias";
    public static final String AUDIT_SSL_JKS_TRUST_ALIAS = "ca_alias";
    
    public static final String AUDIT_SSL_PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String AUDIT_SSL_PEMKEY_CONTENT = "pemkey_content";
    public static final String AUDIT_SSL_PEMKEY_PASSWORD = "pemkey_password";
    public static final String AUDIT_SSL_PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String AUDIT_SSL_PEMCERT_CONTENT = "pemcert_content";
    public static final String AUDIT_SSL_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String AUDIT_SSL_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";

    public static final String AUDIT_SSL_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";
    public static final String AUDIT_SSL_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";

	public HttpESAuditLog(final Settings settings, final Path configPath, ThreadPool threadPool,
	        final IndexNameExpressionResolver resolver, final ClusterService clusterService) throws Exception {

		super(settings, threadPool, resolver, clusterService);

		Settings auditSettings = settings.getAsSettings("searchguard.audit.config");

		servers = auditSettings.getAsArray("http_endpoints", new String[] { "localhost:9200" });
		this.index = auditSettings.get("index", "auditlog6");
		
		try {
            this.indexPattern = DateTimeFormat.forPattern(index);
        } catch (IllegalArgumentException e) {
            log.debug("Unable to parse index pattern due to {}. "
                    + "If you have no date pattern configured you can safely ignore this message", e.getMessage());
        }
		
		this.type = auditSettings.get("type", "auditlog");
		boolean verifyHostnames = auditSettings.getAsBoolean(AUDIT_SSL_VERIFY_HOSTNAMES, true);
		boolean enableSsl = auditSettings.getAsBoolean(AUDIT_SSL_ENABLE_SSL, false);
		boolean enableSslClientAuth = auditSettings.getAsBoolean(AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH , AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT);
		String user = auditSettings.get("username");
		String password = auditSettings.get("password");

		final HttpClientBuilder builder = HttpClient.builder(servers);
		final Environment env = new Environment(settings, configPath);

		if (enableSsl) {
		    
		    final boolean pem = settings.get(AUDIT_SSL_PEMTRUSTEDCAS_FILEPATH, null) != null
                    || settings.get(AUDIT_SSL_PEMTRUSTEDCAS_CONTENT, null) != null;
           
		    
		    if(pem) {
                X509Certificate[] trustCertificates = loadCertificatesFromStream(resolveStream(AUDIT_SSL_PEMTRUSTEDCAS_CONTENT, settings));
                
                if(trustCertificates == null) {
                    trustCertificates = loadCertificatesFromFile(resolve(AUDIT_SSL_PEMTRUSTEDCAS_FILEPATH, settings, configPath, true));
                }
                    //for client authentication
                X509Certificate authenticationCertificate = loadCertificateFromStream(resolveStream(AUDIT_SSL_PEMCERT_CONTENT, settings));
                
                if(authenticationCertificate == null) {
                    authenticationCertificate = loadCertificateFromFile(resolve(AUDIT_SSL_PEMCERT_FILEPATH, settings, configPath, enableClientAuth));
                }
                
                PrivateKey authenticationKey = loadKeyFromStream(settings.get(AUDIT_SSL_PEMKEY_PASSWORD), resolveStream(AUDIT_SSL_PEMKEY_CONTENT, settings));
                
                if(authenticationKey == null) {
                    authenticationKey = loadKeyFromFile(settings.get(AUDIT_SSL_PEMKEY_PASSWORD), resolve(AUDIT_SSL_PEMKEY_FILEPATH, settings, configPath, enableClientAuth));    
                }

                //cc = CredentialConfigFactory.createX509CredentialConfig(trustCertificates, authenticationCertificate, authenticationKey);
                
                if(log.isDebugEnabled()) {
                    log.debug("Use PEM to secure communication with LDAP server (client auth is {})", authenticationKey!=null);
                }
                
            } else {
                final KeyStore trustStore = loadKeyStore(resolve(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, configPath, true)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, DEFAULT_TRUSTSTORE_PASSWORD)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE));
                
                final String[] trustStoreAliases = settings.getAsArray(AUDIT_SSL_JKS_TRUST_ALIAS, null);
                
                //for client authentication
                final KeyStore keyStore = loadKeyStore(resolve(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings, configPath, enableClientAuth)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, DEFAULT_KEYSTORE_PASSWORD)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE));
                final String keyStorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, DEFAULT_KEYSTORE_PASSWORD);
                
                final String keyStoreAlias = settings.get(AUDIT_SSL_JKS_CERT_ALIAS, null);
                final String[] keyStoreAliases = keyStoreAlias==null?null:new String[]{keyStoreAlias};
                
                if(enableSslClientAuth && keyStoreAliases == null) {
                    throw new IllegalArgumentException(AUDIT_SSL_JKS_CERT_ALIAS+" not given");
                }
                
                if(log.isDebugEnabled()) {
                    log.debug("Use Trust-/Keystore to secure communication with LDAP server (client auth is {})", keyStore!=null);
                    log.debug("trustStoreAliases: {}, keyStoreAlias: {}",  Arrays.toString(trustStoreAliases), keyStoreAlias);
                }
                
                //cc = CredentialConfigFactory.createKeyStoreCredentialConfig(trustStore, trustStoreAliases, keyStore, keyStorePassword, keyStoreAliases);

            }
            
		    
		    final String[] enabledCipherSuites = settings.getAsArray(AUDIT_SSL_ENABLED_SSL_CIPHERS, EMPTY_STRING_ARRAY);   
            final String[] enabledProtocols = settings.getAsArray(AUDIT_SSL_ENABLED_SSL_PROTOCOLS, new String[] { "TLSv1.1", "TLSv1.2" });   
            
		    
			builder.enableSsl(
					env.configFile().resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH)).toFile(),
					settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, "changeit"), verifyHostnames);

			if (enableSslClientAuth) {
				builder.setPkiCredentials(
						env.configFile().resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH)).toFile(),
						settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, "changeit"));
			}
		}

		if (user != null && password != null) {
			builder.setBasicCredentials(user, password);
		}

		client = builder.build();
	}

	@Override
	public void close() throws IOException {
		if (client != null) {
			client.close();
		}
	}

	@Override
	public void store(final AuditMessage msg) {
		try {
			boolean successful = client.index(msg.toString(), getExpandedIndexName(indexPattern, index), type, true);

			if (!successful) {
				log.error("Unable to send audit log {} to one of these servers: {}", msg, Arrays.toString(servers));
			}
		} catch (Exception e) {
			log.error("Unable to send audit log {} due to {}", e, msg, e.toString());
		}
	}
}
