package com.floragunn.searchguard.auditlog.impl;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.http.entity.ContentType;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.auditlog.impl.AuditMessage.AuditMessageKey;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.auditlog.impl.WebhookAuditLog.WebhookFormat;

public class WebhookAuditLogTest extends AbstractUnitTest {

	@Test
	public void invalidConfTest() throws Exception {
		AuditMessage msg = MockAuditMessageFactory.validAuditMessage();

		// provide no format, defaults to TEXT
		Settings settings = Settings.settingsBuilder().build();
		MockWebhookAuditLog auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertEquals(null, auditlog.webhookFormat);
	}

	@SuppressWarnings("resource")
	@Test
	public void formatsTest() throws Exception {

		String url = "http://localhost";
		AuditMessage msg = MockAuditMessageFactory.validAuditMessage();

		// provide no format, defaults to TEXT
		Settings settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.build();
		MockWebhookAuditLog auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertEquals(WebhookFormat.TEXT, auditlog.webhookFormat);
		Assert.assertEquals(ContentType.TEXT_PLAIN, auditlog.webhookFormat.getContentType());
		Assert.assertTrue(auditlog.payload, !auditlog.payload.startsWith("{\"text\":"));

		// provide faulty format, defaults to TEXT
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "idonotexist")
				.build();
		auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertEquals(WebhookFormat.TEXT, auditlog.webhookFormat);
		Assert.assertEquals(ContentType.TEXT_PLAIN, auditlog.webhookFormat.getContentType());
		Assert.assertTrue(auditlog.payload, !auditlog.payload.startsWith("{\"text\":"));
		auditlog.close();

		// TEXT
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "text")
				.build();
		auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertEquals(WebhookFormat.TEXT, auditlog.webhookFormat);
		Assert.assertEquals(ContentType.TEXT_PLAIN, auditlog.webhookFormat.getContentType());
		Assert.assertTrue(auditlog.payload, !auditlog.payload.startsWith("{\"text\":"));

		// JSON
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "json")
				.build();
		auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		System.out.println(auditlog.payload);
		Assert.assertEquals(WebhookFormat.JSON, auditlog.webhookFormat);
		Assert.assertEquals(ContentType.APPLICATION_JSON, auditlog.webhookFormat.getContentType());
		Assert.assertTrue(auditlog.payload, !auditlog.payload.startsWith("{\"text\":"));

		// SLACK
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "slack")
				.build();
		auditlog = new MockWebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertEquals(WebhookFormat.SLACK, auditlog.webhookFormat);
		Assert.assertEquals(ContentType.APPLICATION_JSON, auditlog.webhookFormat.getContentType());
		Assert.assertTrue(auditlog.payload, auditlog.payload.startsWith("{\"text\":"));
	}

	@Test
	@SuppressWarnings("resource")
	public void postFaultyServerTest() throws Exception {

		String url = "faultyurl";

		final Settings settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "slack")
				.build();

		MockWebhookAuditLog auditlog = new MockWebhookAuditLog(settings);
		AuditMessage msg = MockAuditMessageFactory.validAuditMessage();
		auditlog.save(msg);
		Assert.assertEquals(null, auditlog.url);
		Assert.assertEquals(null, auditlog.payload);
		Assert.assertEquals(null, auditlog.webhookUrl);
	}

	@Test
	public void postTestHttp() throws Exception {
		TestHttpHandler handler = new TestHttpHandler();

		HttpServer server = ServerBootstrap.bootstrap()
				.setListenerPort(8080)
				.setServerInfo("Test/1.1")
				.registerHandler("*", handler)
				.create();

		server.start();

		String url = "http://localhost:8080/endpoint";
		
		// SLACK
		Settings settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "slack")
				.build();

		WebhookAuditLog auditlog = new WebhookAuditLog(settings);
		AuditMessage msg = MockAuditMessageFactory.validAuditMessage();
		auditlog.save(msg);
		Assert.assertTrue(handler.method.equals("POST"));
		Assert.assertTrue(handler.body != null);
		Assert.assertTrue(handler.body.startsWith("{\"text\":"));
		assertStringContainsAllKeysAndValues(handler.body);

		// TEXT
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "texT")
				.build();

		auditlog = new WebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertTrue(handler.method.equals("POST"));
		Assert.assertTrue(handler.body != null);
		Assert.assertFalse(handler.body.contains("{"));
		assertStringContainsAllKeysAndValues(handler.body);
				
		// JSON
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "JSon")
				.build();

		auditlog = new WebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertTrue(handler.method.equals("POST"));
		Assert.assertTrue(handler.body != null);
		Assert.assertTrue(handler.body.contains("{"));
		assertStringContainsAllKeysAndValues(handler.body);
		
		// URL POST
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "URL_PARAMETER_POST")
				.build();

		auditlog = new WebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertTrue(handler.method.equals("POST"));
		Assert.assertTrue(handler.body.equals(""));
		Assert.assertTrue(!handler.body.contains("{"));
		assertStringContainsAllKeysAndValues(URLDecoder.decode(handler.uri, StandardCharsets.UTF_8.displayName()));
		
		// URL GET
		settings = Settings.settingsBuilder()
				.put("searchguard.audit.config.webhook_url", url)
				.put("searchguard.audit.config.webhook_format", "URL_PARAMETER_GET")
				.build();

		auditlog = new WebhookAuditLog(settings);
		auditlog.save(msg);
		Assert.assertTrue(handler.method.equals("GET"));
		Assert.assertTrue(handler.body.equals(""));
		Assert.assertTrue(!handler.body.contains("{"));
		assertStringContainsAllKeysAndValues(URLDecoder.decode(handler.uri, StandardCharsets.UTF_8.displayName()));
	}

	private void assertStringContainsAllKeysAndValues(String in) {
		AuditMessageKey[] allKeys = AuditMessageKey.values();
		for (AuditMessageKey auditMessageKey : allKeys) {
			Assert.assertTrue(in.contains(auditMessageKey.getName()));
		}
		Assert.assertTrue(in.contains(Category.FAILED_LOGIN.name()));
		Assert.assertTrue(in.contains("Forbidden"));
		Assert.assertTrue(in.contains("Details"));
		Assert.assertTrue(in.contains("John Doe"));
		Assert.assertTrue(in.contains("8.8.8.8"));
		Assert.assertTrue(in.contains("CN=kirk,OU=client,O=client,L=test,C=DE"));
	}
}
