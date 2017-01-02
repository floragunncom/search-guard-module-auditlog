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

import java.net.InetSocketAddress;

import org.apache.http.Header;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.junit.Assert;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.configuration.ConfigurationService;
import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.test.AbstractSGUnitTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.cluster.ClusterHelper;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;

public abstract class AbstractAuditlogiUnitTest extends AbstractSGUnitTest {

	protected void setup() throws Exception {
		setup(ClusterConfiguration.DEFAULT);
	}

	protected void setup(ClusterConfiguration configuration) throws Exception {
		final Settings nodeSettings = defaultNodeSettings(true);

		log.debug("Starting nodes");
		this.ci = ch.startCluster(nodeSettings, configuration);
		log.debug("Started nodes");

		log.debug("Setup index");
		setupSearchGuardIndex();
		log.debug("Setup done");

		RestHelper rh = new RestHelper(ci);

		this.rh = rh;
	}

	protected void setupStarfleetIndex() throws Exception {
		final boolean sendHTTPClientCertificate = rh.sendHTTPClientCertificate;
		final String keystore = rh.keystore;
		rh.sendHTTPClientCertificate = true;
		rh.keystore = "kirk-keystore.jks";
		rh.executePutRequest("sf", null, new Header[0]);
		rh.executePutRequest("sf/ships/0?refresh", "{\"number\" : \"NCC-1701-D\"}", new Header[0]);
		rh.executePutRequest("sf/public/0?refresh", "{\"some\" : \"value\"}", new Header[0]);
		rh.executePutRequest("sf/public/0?refresh", "{\"some\" : \"value\"}", new Header[0]);
		rh.sendHTTPClientCertificate = sendHTTPClientCertificate;
		rh.keystore = keystore;
	}

	protected void setupSearchGuardIndex() {
		Settings tcSettings = Settings.builder().put("cluster.name", ClusterHelper.clustername)
				.put(defaultNodeSettings(false))
				.put("searchguard.ssl.transport.keystore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
				.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "kirk").put("path.home", ".").build();

		try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class)
				.addPlugin(SearchGuardPlugin.class).build()) {

			log.debug("Start transport client to init");

			tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(ci.nodeHost, ci.nodePort)));
			Assert.assertEquals(ci.numNodes,
					tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);

			tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();

			tc.index(new IndexRequest("searchguard").type("dummy").id("0").refresh(true)
					.source(FileHelper.readYamlContent("sg_config.yml"))).actionGet();

			tc.index(new IndexRequest("searchguard").type("config").id("0").refresh(true)
					.source(FileHelper.readYamlContent("sg_config.yml"))).actionGet();
			tc.index(new IndexRequest("searchguard").type("internalusers").refresh(true).id("0")
					.source(FileHelper.readYamlContent("sg_internal_users.yml"))).actionGet();
			tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true)
					.source(FileHelper.readYamlContent("sg_roles.yml"))).actionGet();
			tc.index(new IndexRequest("searchguard").type("rolesmapping").refresh(true).id("0")
					.source(FileHelper.readYamlContent("sg_roles_mapping.yml"))).actionGet();
			tc.index(new IndexRequest("searchguard").type("actiongroups").refresh(true).id("0")
					.source(FileHelper.readYamlContent("sg_action_groups.yml"))).actionGet();

			ConfigUpdateResponse cur = tc
					.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(ConfigurationService.CONFIGNAMES))
					.actionGet();
			Assert.assertEquals(ci.numNodes, cur.getNodes().length);

		}
	}

	protected Settings defaultNodeSettings(boolean enableRestSSL) {
		Settings.Builder builder = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
				.put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
				.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, false)
				.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
				.put("searchguard.ssl.transport.keystore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
				.put("searchguard.ssl.transport.truststore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
				.put("searchguard.ssl.transport.enforce_hostname_verification", false)
				.put("searchguard.ssl.transport.resolve_hostname", false)
				.putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
				.put(additionalSettings);

		if (enableRestSSL) {
			builder.put("searchguard.ssl.http.enabled", true)
					.put("searchguard.ssl.http.keystore_filepath",
							FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
					.put("searchguard.ssl.http.truststore_filepath",
							FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"));
		}
		return builder.build();
	}
	
	protected Settings additionalSettings = Settings.EMPTY;
}
