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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

public final class AuditLogImpl extends AbstractAuditLog {
    
	// package private for unit tests :(
    final ExecutorService pool;
    
    private boolean useExecutorService = true;
    
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
    public AuditLogImpl(final Settings settings, Provider<Client> clientProvider, ThreadPool threadPool,
            final IndexNameExpressionResolver resolver, final Provider<ClusterService> clusterService) {
    	super(settings, threadPool, resolver, clusterService);
        String type = settings.get("searchguard.audit.type", null);
        // thread pool size of 0 means we directly hand the message to the delegate,
        // skipping the thread pool altogether
        Integer threadPoolSize = settings.getAsInt("searchguard.audit.threadpool.size", 10);
        if (threadPoolSize <= 0) {
        	this.useExecutorService = false;
        	this.pool = null;
        } else {
        	this.pool = Executors.newFixedThreadPool(threadPoolSize);	
        }        
        String index = settings.get("searchguard.audit.config.index","auditlog");
        String doctype = settings.get("searchguard.audit.config.type","auditlog");
        
		if (type != null) {
			switch (type.toLowerCase()) {
			case "internal_elasticsearch":
				delegate = new ESAuditLog(settings, clientProvider, threadPool, index, doctype, resolver, clusterService);
				break;
			case "external_elasticsearch":
				try {
					delegate = new HttpESAuditLog(settings, threadPool, resolver, clusterService);
				} catch (Exception e) {
					log.error("Audit logging unavailable: Unable to setup HttpESAuditLog due to {}", e, e.toString());
				}
				break;
			case "webhook":
				delegate = new WebhookAuditLog(settings, threadPool, resolver, clusterService);
				break;				
			case "debug":
				delegate = new DebugAuditLog(settings, threadPool, resolver, clusterService);
				break;
			default:
                try {
                    Class<?> delegateClass = Class.forName(type);

                    if (AbstractAuditLog.class.isAssignableFrom(delegateClass)) {
                        try {
                            delegate = (AbstractAuditLog) delegateClass.getConstructor(Settings.class, ThreadPool.class).newInstance(settings, threadPool);
                        } catch (Throwable e) {
                            delegate = (AbstractAuditLog) delegateClass.getConstructor(Settings.class, ThreadPool.class, IndexNameExpressionResolver.class, Provider.class)
                                    .newInstance(settings, threadPool, resolver, clusterService);
                        }
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
        
        if(pool != null) {
            pool.shutdown(); // Disable new tasks from being submitted
                    
            try {
              // Wait a while for existing tasks to terminate
              if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                pool.shutdownNow(); // Cancel currently executing tasks
                // Wait a while for tasks to respond to being cancelled
                if (!pool.awaitTermination(60, TimeUnit.SECONDS))
                    log.error("Pool did not terminate");
              }
            } catch (InterruptedException ie) {
              // (Re-)Cancel if current thread also interrupted
              pool.shutdownNow();
              // Preserve interrupt status
              Thread.currentThread().interrupt();
            }
        }
    	if(delegate != null) {
        	try {
                log.info("Closing {}", delegate.getClass().getSimpleName());           
                delegate.close();        		
        	} catch(Exception ex) {
                log.info("Could not close delegate '{}' due to '{}'", delegate.getClass().getSimpleName(), ex.getMessage());                   		
        	}
        }
        
    }

    @Override
    protected void save(final AuditMessage msg) {
    	// only save if we have a valid delegate
        if(delegate != null) {
        	// if the configured thread pool is 
        	if(useExecutorService) {
            	saveAsync(msg);          		
        	} else {
        		delegate.save(msg);
        	}
        }
    }
    
    protected void saveAsync(final AuditMessage msg) {
    	try {
        	pool.submit(new Runnable() {				
    			@Override
    			public void run() {
    				delegate.save(msg);
    				
    			}
    		});                    		    		
    	} catch(Exception ex) {
            log.error("Could not submit audit message to thread pool for delegate '{}' due to '{}'", delegate.getClass().getSimpleName(), ex.getMessage());                   		
    	}
    }
}
