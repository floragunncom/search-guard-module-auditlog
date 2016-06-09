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
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

public final class AuditLogImpl extends AbstractAuditLog {
    
    //config in elasticsearch.yml

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private AbstractAuditLog delegate;  

    @Inject
    public AuditLogImpl(final Settings settings, Client esclient) {
        String type = settings.get("searchguard.audit.type", null);
        
        String index = settings.get("searchguard.audit.config.index","auditlog");
        String doctype = settings.get("searchguard.audit.config.type","auditlog");
        
        if(type != null && (type.equals(ESAuditLog.class.getName()) || type.equalsIgnoreCase("internal_elasticsearch"))) {
            delegate = new ESAuditLog(esclient, index, doctype);
        } else if(type != null && (type.equals(HttpESAuditLog.class.getName()) || type.equalsIgnoreCase("external_elasticsearch"))) {
            try {
                delegate = new HttpESAuditLog(settings);
            } catch (Exception e) {
                log.error("Unable to setup HttpESAuditLog due to {}", e, e.toString());
                throw new RuntimeException("Unable to setup HttpESAuditLog due to "+e.toString(), e);
            }
        } else if ("debug".equals(type)) {
            delegate = new DebugAuditLog();
        } else {
            delegate = null;
        }
        
        if(delegate != null) {
            log.info("Delegate class {}", delegate.getClass());
        } else {
            log.info("Audit log available but disabled");
        }
        
        
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                Runtime.getRuntime().addShutdownHook(new Thread() {

                    @Override
                    public void run() {
                        try {
                            close();
                        } catch (IOException e) {
                            log.warn("Exception while shutting down audit log {}", delegate);
                        }
                    }           
                });
                return null;
            }
        });
    }

    @Override
    public void close() throws IOException {
        if(delegate != null) {
            log.info("Close {}", delegate.getClass().getSimpleName());
            
            delegate.close();
        }
    }

    @Override
    protected void save(final AuditMessage msg) {
        if(delegate != null) {
            delegate.save(msg);
        }
    }
}
