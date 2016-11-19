package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;

class WebhookAuditLog extends AbstractAuditLog {

	/* HttpClient is thread safe */
	private final static CloseableHttpClient httpClient = HttpClients.createDefault();

	String webhookUrl = null;
	WebhookFormat webhookFormat = null;

	WebhookAuditLog(final Settings settings) {
		super(settings);
		Settings auditSettings = settings.getAsSettings("searchguard.audit.config");
		String webhookUrl = auditSettings.get("webhook_url");
		String format = auditSettings.get("webhook_format");

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
		// nothing to close
	}

	boolean get(AuditMessage msg) {
		return doGet(webhookUrl + msg.toUrlParameters());
	}

	boolean doGet(String url) {
		HttpGet httpGet = new HttpGet(url);
		InputStream inStream = null;
		CloseableHttpResponse serverResponse = null;
		try {
			serverResponse = httpClient.execute(httpGet);
			inStream = serverResponse.getEntity().getContent();
			String responseAsString = IOUtils.toString(inStream);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot GET to webhook URL '{}', server returned status {} and message {}", webhookUrl, responseCode,
						responseAsString);
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
			IOUtils.closeQuietly(inStream);
		}
	}

	boolean post(AuditMessage msg) {

		String payload;

		switch (webhookFormat) {
		case JSON:
			payload = msg.toJson();
			break;
		case TEXT:
			payload = msg.toText();
			break;
		case SLACK:
			payload = "{\"text\": \"" + msg.toText() + "\"}";
			break;
		case URL_PARAMETER_POST:
			payload = "";
			break;
		default:
			log.error("WebhookFormat '{}' not implemented yet", webhookFormat.name());
			return false;
		}

		if (webhookFormat.equals(WebhookFormat.URL_PARAMETER_POST)) {
			return doPost(webhookUrl + msg.toUrlParameters(), payload);
		} else {
			return doPost(webhookUrl, payload);
		}

	}

	boolean doPost(String url, String payload) {

		HttpPost postRequest = new HttpPost(url);

		StringEntity input = new StringEntity(payload, StandardCharsets.UTF_8);
		input.setContentType(webhookFormat.contentType.toString());
		postRequest.setEntity(input);

		CloseableHttpResponse serverResponse = null;
		InputStream inStream = null;
		try {
			serverResponse = httpClient.execute(postRequest);
			inStream = serverResponse.getEntity().getContent();
			String responseAsString = IOUtils.toString(inStream);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot POST to webhook URL '{}', server returned status {} and message {}", webhookUrl, responseCode,
						responseAsString);
				return false;
			}
			return true;
		} catch (IOException e) {
			log.error("Cannot POST to webhook URL '{}'", e, webhookUrl);
			return false;
		} finally {
			try {
				if (serverResponse != null) {
					serverResponse.close();
				}
			} catch (IOException e) {
				log.error("Cannot close server response '{}'", e);
			}
			IOUtils.closeQuietly(inStream);
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
