package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;

class WebhookAuditLog extends AbstractAuditLog {
	
	/* HttpClient is thread safe */
	//private final static CloseableHttpClient httpClient = HttpClients.createDefault();
	private final CloseableHttpClient httpClient;
	
	String webhookUrl = null;
	WebhookFormat webhookFormat = null;

	WebhookAuditLog(final Settings settings) {
		super(settings);
		Settings auditSettings = settings.getAsSettings("searchguard.audit.config");
		
		String webhookUrl = auditSettings.get("webhook_url");
		String format = auditSettings.get("webhook_format");
		
		Boolean verifySSL = auditSettings.getAsBoolean("ssl.verify", Boolean.TRUE);
		httpClient = getInsecureHttpClient(verifySSL);
		
		if(httpClient == null) {
			log.error("Could not create HttpClient, audit log not available.");
			return;			
		}
		
		if (Strings.isEmpty(webhookUrl)) {
			log.error("searchguard.audit.config.webhook_url not provided, webhook audit log will not work");
			return;
		} else {
			try {
				// Sanity - check URL validity
				new URL(webhookUrl);
				this.webhookUrl = webhookUrl;
			} catch (MalformedURLException ex) {
				log.error("URL {} is invalid, webhook audit log will not work.", ex, webhookUrl);
			}
		}

		if (Strings.isEmpty(format)) {
			log.warn("searchguard.audit.config.webhook_format not provided, falling back to 'text'");
			webhookFormat = WebhookFormat.TEXT;
		} else {
			try {
				webhookFormat = WebhookFormat.valueOf(format.toUpperCase());
			} catch (Exception ex) {
				log.error("Could not find WebhookFormat for type {}, falling back to 'text'", ex, format);
				webhookFormat = WebhookFormat.TEXT;
			}
		}
	}

	@Override
	protected void save(AuditMessage msg) {
		if (Strings.isEmpty(webhookUrl)) {
			log.debug("Webhook URL is null");
			return;
		}
		if (msg == null) {
			log.debug("Message is null");
			return;
		}
		if (msg.getCategory().isEnabled()) {
			switch (webhookFormat.method) {
			case POST:
				post(msg);
				break;
			case GET:
				get(msg);
				break;
			default:
				log.error("Http Method '{}' defined in WebhookFormat '{}' not implemented yet", webhookFormat.method.name(),
						webhookFormat.name());
				return;
			}
		}
	}

    @Override
    public void close() throws IOException {
                
        if(httpClient != null) {
        	httpClient.close();
        }
        
    }

	
	/**
	 * Transforms an {@link AuditMessage} to JSON. By default, all fields are
	 * included in the JSON string. This method can be overridden by subclasses
	 * if a specific JSON format is needed. 
	 * 
	 * @param msg the AuditMessage to transform
	 * @return the JSON string
	 */
	protected String formatJson(final AuditMessage msg) {
		return msg.toJson();
	}

	/**
	 * Transforms an {@link AuditMessage} to plain text. This method can be overridden 
	 * by subclasses if a specific text format is needed. 
	 * 
	 * @param msg the AuditMessage to transform
	 * @return the text string
	 */	
	protected String formatText(AuditMessage msg) {
		return msg.toText();
	}

	/**
	 * Transforms an {@link AuditMessage} to Slack format. 
	 * The default implementation returns
	 * <p><blockquote><pre>
	 * {
	 *   "text": "<AuditMessage#toText>"
	 * }    
	 * </pre></blockquote>
	 * <p> 
	 * Can be overridden by subclasses if a more specific format is needed.
	 * 
	 * @param msg the AuditMessage to transform
	 * @return the Slack formatted JSON string
	 */	
	protected String formatSlack(AuditMessage msg) {
		return "{\"text\": \"" + msg.toText() + "\"}";
	}	
	
	/**
	 * Transforms an {@link AuditMessage} to a query parameter String. 
	 * Used by {@link WebhookFormat#URL_PARAMETER_GET} and
	 * Used by {@link WebhookFormat#URL_PARAMETER_POST}. Can be overridden by
	 * subclasses if a specific format is needed.
	 * 
	 * @param msg the AuditMessage to transform
	 * @return the query parameter string
	 */	
	protected String formatUrlParameters(AuditMessage msg) {
		return msg.toUrlParameters();
	}
	
	boolean get(AuditMessage msg) {
		switch (webhookFormat) {
		case URL_PARAMETER_GET:
			return doGet(webhookUrl + formatUrlParameters(msg));	
		default:
			log.error("WebhookFormat '{}' not implemented yet", webhookFormat.name());
			return false;
		}		
	}

	boolean doGet(String url) {
		HttpGet httpGet = new HttpGet(url);
		CloseableHttpResponse serverResponse = null;
		try {
			serverResponse = httpClient.execute(httpGet);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot GET to webhook URL '{}', server returned status {}", webhookUrl, responseCode);
				return false;
			}
			return true;
		} catch (IOException e) {
			log.error("Cannot GET to webhook URL '{}'", e, webhookUrl);
			return false;
		} finally {
			try {
				if (serverResponse != null) {
					serverResponse.close();
				}
			} catch (IOException e) {
				log.error("Cannot close server response '{}'", e);
			}			
		}
	}

	boolean post(AuditMessage msg) {

		String payload;
		String url = webhookUrl;
		
		switch (webhookFormat) {
		case JSON:
			payload = formatJson(msg);
			break;
		case TEXT:
			payload = formatText(msg);
			break;
		case SLACK:
			payload = "{\"text\": \"" + msg.toText() + "\"}";
			break;
		case URL_PARAMETER_POST:
			payload = "";
			url = webhookUrl + formatUrlParameters(msg);
			break;
		default:
			log.error("WebhookFormat '{}' not implemented yet", webhookFormat.name());
			return false;
		}
		
		return doPost(url, payload);

	}
	
	boolean doPost(String url, String payload) {

		HttpPost postRequest = new HttpPost(url);

		StringEntity input = new StringEntity(payload, StandardCharsets.UTF_8);
		input.setContentType(webhookFormat.contentType.toString());
		postRequest.setEntity(input);

		CloseableHttpResponse serverResponse = null;
		try {
			serverResponse = httpClient.execute(postRequest);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot POST to webhook URL '{}', server returned status {}", webhookUrl, responseCode);
				return false;
			}
			return true;
		} catch (IOException e) {
			log.error("Cannot POST to webhook URL '{}' due to '{}'", webhookUrl, e.getMessage());
			return false;
		} finally {
			try {
				if (serverResponse != null) {
					serverResponse.close();
				}
			} catch (IOException e) {
				log.error("Cannot close server response", e);
			}
		}
	}

	CloseableHttpClient getInsecureHttpClient(Boolean verifySsl)  {

        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;
        
        RequestConfig config = RequestConfig.custom()
          .setConnectTimeout(timeout * 1000)
          .setConnectionRequestTimeout(timeout * 1000)
          .setSocketTimeout(timeout * 1000).build();

        
		// default client verifies SSL certificates
		if(verifySsl) {
			return HttpClients.custom().setDefaultRequestConfig(config).build();
		}

		// We disable all ssl checks. Not recommended for production, and will likely
		// become more configurable in subsequent releases.
	    TrustStrategy trustStrategy = new TrustStrategy() {
	        @Override
	        public boolean isTrusted(X509Certificate[] chain, String authType) {
	            return true;
	        }
	    };

	    HostnameVerifier hostnameVerifier = new HostnameVerifier() {
	        @Override
	        public boolean verify(String hostname, SSLSession session) {
	            return true;
	        }
	    };
	    
	    try {
		    return HttpClients.custom()
		            .setSSLSocketFactory(new SSLConnectionSocketFactory(new SSLContextBuilder().loadTrustMaterial(trustStrategy).build(),hostnameVerifier))
		            .setDefaultRequestConfig(config)
		            .build();	    	
	    }catch(Exception ex) {
	    	log.error("Could not create HTTPClient due to {}, audit log not available.", ex.getMessage());
	    	return null;
	    }
	}
	
	public static enum WebhookFormat {
		URL_PARAMETER_GET(HttpMethod.GET, ContentType.TEXT_PLAIN),
		URL_PARAMETER_POST(HttpMethod.POST, ContentType.TEXT_PLAIN),
		TEXT(HttpMethod.POST, ContentType.TEXT_PLAIN),
		JSON(HttpMethod.POST, ContentType.APPLICATION_JSON),
		SLACK(HttpMethod.POST, ContentType.APPLICATION_JSON);

		private HttpMethod method;
		private ContentType contentType;

		private WebhookFormat(HttpMethod method, ContentType contentType) {
			this.method = method;
			this.contentType = contentType;
		}

		HttpMethod getMethod() {
			return method;
		}

		ContentType getContentType() {
			return contentType;
		}
		
		
	}

	private static enum HttpMethod {
		GET,
		POST;
	}


}
