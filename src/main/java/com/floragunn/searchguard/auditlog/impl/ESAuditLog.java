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

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.ContextAndHeaderHolder;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;

import com.floragunn.searchguard.support.ConfigConstants;

public final class ESAuditLog extends AbstractAuditLog {
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<Client> clientProvider;
    private final String index;
    private final String type;

    public ESAuditLog(final Settings settings, final Provider<Client> clientProvider, String index, String type,
            final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService) {
        super(settings, resolver, clusterService);
        this.clientProvider = clientProvider;
        this.index = index;
        this.type = type;
    }

    @Override
    public void close() throws IOException {

    }

    @Override
    protected void save(final AuditMessage msg) {

        try {
            final IndexRequestBuilder irb = clientProvider.get().prepareIndex(index, type).setRefresh(true).setSource(msg.getAsMap());
            irb.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
            irb.setTimeout(TimeValue.timeValueMinutes(1));
            irb.execute(new ActionListener<IndexResponse>() {

                @Override
                public void onResponse(final IndexResponse response) {
                    if(log.isTraceEnabled()) {
                        log.trace("audit message {} written to {}/{}", msg,response.getIndex(), response.getType());
                    }
                }

                @Override
                public void onFailure(final Throwable e) {
                    log.error("Unable to write audit log {} due to {}", e, msg, e.toString());
                }
            });
        } catch (final Exception e) {
            log.error("Unable to write audit log {} due to {}", e, msg, e.toString());
        }
    }

    @Override
    protected void checkAndSave(final ContextAndHeaderHolder request, String action, final AuditMessage msg) {
        if (Boolean.parseBoolean((String) request.getHeader(ConfigConstants.SG_CONF_REQUEST_HEADER))) {
            return;
        }
        super.checkAndSave(request, action, msg);      
    }
}
