/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 */

package com.floragunn.searchguard.auditlog.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;

public abstract class AbstractUnitTest {

    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.vendor") + " "
                + System.getProperty("java.vm.name"));
    }
    
    public static final ThreadPool MOCK_POOL = new ThreadPool(Settings.builder().put("node.name",  "mock").build());

    @Rule
    public TestName name = new TestName();
    protected final String clustername = "searchguard_ssl_testcluster";

    private Node esNode1;
    private Node esNode2;
    private Node esNode3;
    protected String httpHost = null;
    protected int httpPort = -1;
    protected String nodeHost;
    protected int nodePort;
    protected boolean enableHTTPClientSSL = false;
    protected boolean enableHTTPClientSSLv3Only = false;
    protected boolean sendHTTPClientCertificate = false;
    protected boolean trustHTTPServerCertificate = false;

    @Rule
    public final TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("---------------- Starting JUnit-test: " + className + " " + methodName + " ----------------");
        }

        @Override
        protected void failed(final Throwable e, final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println(">>>> " + className + " " + methodName + " FAILED due to " + e);
        }

        @Override
        protected void finished(final Description description) {
            // System.out.println("-----------------------------------------------------------------------------------------");
        }

    };

    protected AbstractUnitTest() {
        super();
    }

    // @formatter:off
    private Settings.Builder getDefaultSettingsBuilder(final int nodenum, final boolean dataNode, final boolean masterNode) {

        return Settings.builder()
                .put("node.name", "searchguard_testnode_" + nodenum)
                .put("node.data", dataNode)
                .put("node.master", masterNode)
                .put("cluster.name", clustername)
                .put("path.data", "data/data")
                .put("path.conf", "data/config")
                .put("http.enabled", !dataNode)
                .put("cluster.routing.allocation.disk.watermark.high","1mb")
                .put("cluster.routing.allocation.disk.watermark.low","1mb")
                .put("http.cors.enabled", true)
                .put("node.local", false)
                .put("path.home",".")
                .put("node.max_local_storage_nodes",3);
    }
    // @formatter:on

    protected final Logger log = LogManager.getLogger(this.getClass());

    protected final String getHttpServerUri() {
        final String address = "http" + (enableHTTPClientSSL ? "s" : "") + "://" + httpHost + ":" + httpPort;
        log.debug("Connect to {}", address);
        return address;
    }

    public final void startES(final Settings settings) throws Exception {

        FileUtils.deleteDirectory(new File("data"));

        esNode1 = new PluginAwareNode(getDefaultSettingsBuilder(1, false, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Netty4Plugin.class, SearchGuardSSLPlugin.class);
        esNode2 = new PluginAwareNode(getDefaultSettingsBuilder(2, true, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Netty4Plugin.class,SearchGuardSSLPlugin.class);
        esNode3 = new PluginAwareNode(getDefaultSettingsBuilder(3, true, false).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Netty4Plugin.class,SearchGuardSSLPlugin.class);

        esNode1.start();
        esNode2.start();
        esNode3.start();

        waitForGreenClusterState(esNode1.client());
    }

    @Before
    public void setUp() throws Exception {
        enableHTTPClientSSL = false;
        enableHTTPClientSSLv3Only = false;
    }

    @After
    public void tearDown() throws Exception {

        if (esNode3 != null) {
            esNode3.close();
        }

        if (esNode2 != null) {
            esNode2.close();
        }

        if (esNode1 != null) {
            esNode1.close();
        }
    }

    protected void waitForGreenClusterState(final Client client) throws IOException {
        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(30), client);
    }

    protected void waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final Client client) throws IOException {
        try {
            log.debug("waiting for cluster state {}", status.name());
            final ClusterHealthResponse healthResponse = client.admin().cluster().prepareHealth().setWaitForStatus(status)
                    .setTimeout(timeout).setWaitForNodes("3").execute().actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException("cluster state is " + healthResponse.getStatus().name() + " with "
                        + healthResponse.getNumberOfNodes() + " nodes");
            } else {
                log.debug("... cluster state ok " + healthResponse.getStatus().name() + " with " + healthResponse.getNumberOfNodes()
                        + " nodes");
            }

            final NodesInfoResponse res = esNode1.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

            final List<NodeInfo> nodes = res.getNodes();

            for (NodeInfo nodeInfo: nodes) {
                if (nodeInfo.getHttp() != null && nodeInfo.getHttp().address() != null) {
                    final InetSocketTransportAddress is = (InetSocketTransportAddress) nodeInfo.getHttp().address().publishAddress();
                    httpPort = is.getPort();
                    httpHost = is.getHost();
                }

                final InetSocketTransportAddress is = (InetSocketTransportAddress) nodeInfo.getTransport().getAddress().publishAddress();
                nodePort = is.getPort();
                nodeHost = is.getHost();
            }
        } catch (final ElasticsearchTimeoutException e) {
            throw new IOException("timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
    }

    public File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = AbstractUnitTest.class.getClassLoader().getResource(fileNameFromClasspath);
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

    protected String executeSimpleRequest(final String request) throws Exception {

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse response = null;
        try {
            httpClient = getHTTPClient();
            response = httpClient.execute(new HttpGet(getHttpServerUri() + "/" + request));

            if (response.getStatusLine().getStatusCode() >= 300) {
                throw new Exception("Statuscode " + response.getStatusLine().getStatusCode()+" - "+response.getStatusLine().getReasonPhrase()+ "-" +IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8));
            }

            return IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        } finally {

            if (response != null) {
                response.close();
            }

            if (httpClient != null) {
                httpClient.close();
            }
        }
    }

    protected final CloseableHttpClient getHTTPClient() throws Exception {

        final HttpClientBuilder hcb = HttpClients.custom();

        if (enableHTTPClientSSL) {

            log.debug("Configure HTTP client with SSL");

            final KeyStore myTrustStore = KeyStore.getInstance("JKS");
            myTrustStore.load(new FileInputStream(getAbsoluteFilePathFromClassPath("truststore.jks")), "changeit".toCharArray());

            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(getAbsoluteFilePathFromClassPath("node-0-keystore.jks")), "changeit".toCharArray());

            final SSLContextBuilder sslContextbBuilder = SSLContexts.custom().useTLS();

            if (trustHTTPServerCertificate) {
                sslContextbBuilder.loadTrustMaterial(myTrustStore);
            }

            if (sendHTTPClientCertificate) {
                sslContextbBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray());
            }

            final SSLContext sslContext = sslContextbBuilder.build();

            String[] protocols = null;

            if (enableHTTPClientSSLv3Only) {
                protocols = new String[] { "SSLv3" };
            } else {
                protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
            }

            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, protocols, null,
                    SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            hcb.setSSLSocketFactory(sslsf);
        }

        hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60 * 1000).build());

        return hcb.build();
    }
}
