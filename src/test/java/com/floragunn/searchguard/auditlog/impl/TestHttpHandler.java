package com.floragunn.searchguard.auditlog.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.RequestLine;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;

public class TestHttpHandler implements HttpRequestHandler {
	String method;
	String uri;
	String body;
	
	@Override
	public void handle(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException, IOException {
		RequestLine requestLine = request.getRequestLine();
		this.method = requestLine.getMethod();
		this.uri = requestLine.getUri();
		
		HttpEntity entity = null;
		if (request instanceof HttpEntityEnclosingRequest) {
			entity = ((HttpEntityEnclosingRequest) request).getEntity();
			body = EntityUtils.toString(entity, StandardCharsets.UTF_8);
		}
	}

}
