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
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

public final class AuditLogImpl extends AbstractAuditLog {

    AbstractAuditLog delegate;
    
    public static void printLicenseInfo() {
        System.out.println("***************************************************");
        System.out.println("Search Guard Audit Log is not free software");
        System.out.println("for commercial use in production.");
        System.out.println("You have to obtain a license if you ");
        System.out.println("use it in production.");
        System.out.println("***************************************************");
    }

    static {
        printLicenseInfo();
    }

    @Inject
    public AuditLogImpl(final Settings settings, Client esclient, ThreadPool threadPool) {
    	super(settings, threadPool);
        String type = settings.get("searchguard.audit.type", null);
        
        String index = settings.get("searchguard.audit.config.index","auditlog");
        String doctype = settings.get("searchguard.audit.config.type","auditlog");
        
		if (type != null) {
			switch (type.toLowerCase()) {
			case "internal_elasticsearch":
				delegate = new ESAuditLog(settings, esclient, index, doctype, threadPool);
				break;
			case "external_elasticsearch":
				try {
					delegate = new HttpESAuditLog(settings, threadPool);
				} catch (Exception e) {
					log.error("Audit logging unavailable: Unable to setup HttpESAuditLog due to {}", e, e.toString());
				}
				break;
			case "debug":
				delegate = new DebugAuditLog(settings, threadPool);
				break;
			default:
                try {
                    Class<?> delegateClass = Class.forName(type);

                    if (AbstractAuditLog.class.isAssignableFrom(delegateClass)) {
                        delegate = (AbstractAuditLog) delegateClass.getConstructor(Settings.class, ThreadPool.class).newInstance(settings, threadPool);
                    } else {
                        log.error("Audit logging unavailable: '{}' is not a subclass of {}", type, AbstractAuditLog.class.getSimpleName());
                    }
                } catch (Throwable e) { //we need really catch a Throwable here!
                    log.error("Audit logging unavailable: Cannot instantiate object of class {} due to {}", e, type, e.toString());
                }
			}
		}

        if(delegate != null) {
            log.info("Audit Log class: {}", delegate.getClass().getSimpleName());
            
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                log.debug("Security Manager present");
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
                    log.debug("Shutdown Hook registered");
                    return null;
                }
            });
            
        } else {
            log.info("Audit Log available but disabled");
        }        
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

    @Override
    protected void checkAndSave(TransportRequest request, AuditMessage msg) {
        if(delegate != null) {
            delegate.checkAndSave(request, msg);
        }
    }

    @Override
    protected void checkAndSave(RestRequest request, AuditMessage msg) {
        if(delegate != null) {
            delegate.checkAndSave(request, msg);
        }
    }
}
