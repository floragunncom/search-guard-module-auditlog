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

package com.floragunn.searchguard.test.helper.file;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.test.AbstractSGUnitTest;
import com.floragunn.searchguard.test.helper.content.ContentHelper;

public class FileHelper {

	protected final static ESLogger log = Loggers.getLogger(FileHelper.class);

	public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
		File file = null;
		final URL fileUrl = AbstractSGUnitTest.class.getClassLoader().getResource(fileNameFromClasspath);
		if (fileUrl != null) {
			try {
				file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
			} catch (final UnsupportedEncodingException e) {
				return null;
			}

			if (file.exists() && file.canRead()) {
				return file;
			} else {
				log.error("Cannot read from {}, maybe the file does not exists? ", file.getAbsolutePath());
			}

		} else {
			log.error("Failed to load " + fileNameFromClasspath);
		}
		return null;
	}

	public static final String loadFile(final String file) throws IOException {
		final StringWriter sw = new StringWriter();
		IOUtils.copy(FileHelper.class.getResourceAsStream("/" + file), sw, StandardCharsets.UTF_8);
		return sw.toString();
	}

	public static XContentBuilder readYamlContent(final String file) {
		try {
			return ContentHelper.readXContent(new StringReader(loadFile(file)), XContentType.YAML);
		} catch (IOException e) {
			return null;
		}
	}


}
