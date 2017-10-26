/*
 * Copyright 2016 by floragunn GmbH - All rights reserved
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.reindex.DeleteByQueryRequest;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;

public final class RequestResolver {
    
    public static List<AuditMessage> resolve(
            final Category category, 
            final Origin origin, 
            final String action, 
            final String privilege, 
            final String effectiveUser, 
            final Boolean sgAdmin, 
            final String initiatingUser, 
            final TransportAddress remoteAddress, 
            final TransportRequest request,
            final Map<String, String> headers,
            final Task task,
            final IndexNameExpressionResolver resolver, 
            final ClusterService cs, 
            final Settings settings, 
            final boolean withDetails, 
            final boolean resolveBulk, 
            final Throwable exception)  {
        
        //final List<AuditMessage> messages = new ArrayList<AuditMessage>(1000);
        
//        if(resolveBulk) {
//            if (request instanceof CompositeIndicesRequest) {
//
//                if(request instanceof BulkShardRequest) {
//
//                    for(BulkItemRequest ar: ((BulkShardRequest) request).items()) {
//                        messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, ar.request(), resolver, cs, settings, withDetails, exception));
//                    }}else
//                
//                if(request instanceof BulkRequest) {
//
//                    for(DocWriteRequest<?> ar: ((BulkRequest) request).requests()) {
//                        messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, ar, resolver, cs, settings, withDetails, exception));
//                    }
//                    
////                } else if(request instanceof MultiGetRequest) {
////                    
////                    for(Item item: ((MultiGetRequest) request).getItems()) {
////                        messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, item, resolver, cs, settings, withDetails, exception));
////                    }
//                    
//                //} else if(request instanceof MultiSearchRequest) {
//                    
//                    //    for(ActionRequest ar: ((MultiSearchRequest) request).requests()) {
//                    //   messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, ar, resolver, cs, settings, withDetails, exception));
//                    //}
//                    
//                } else if(request instanceof MultiTermVectorsRequest) {
////                    
////                    for(ActionRequest ar: (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
////                        messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, ar, resolver, cs, settings, withDetails, exception));
////                    }
//                    
//                    
//                } else {
//                    //log.debug("Can not handle composite request of type '"+request+"' here");
//                }
//                
//            } else {
//                messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, request, resolver, cs, settings, withDetails, exception));
//            }
//            
//        } else {
//            messages.add(resolveInner(category, effectiveUser, sgAdmin, initiatingUser, remoteAddress, action, privilege, origin, request, resolver, cs, settings, withDetails, exception));
//        }
        
        //return messages;
        
        if(resolveBulk && request instanceof BulkShardRequest) { 
            final BulkItemRequest[] innerRequests = ((BulkShardRequest) request).items();
            final List<AuditMessage> messages = new ArrayList<AuditMessage>(innerRequests.length);
            
            for(BulkItemRequest ar: innerRequests) {
                final DocWriteRequest innerRequest = ar.request();
                final AuditMessage msg = resolveInner(
                        category, 
                        effectiveUser, 
                        sgAdmin, 
                        initiatingUser, 
                        remoteAddress, 
                        action, 
                        privilege, 
                        origin, 
                        innerRequest,
                        headers,
                        task,
                        resolver, 
                        cs, 
                        settings, 
                        withDetails, 
                        exception);
                 msg.addShardId(((BulkShardRequest) request).shardId());
                
                messages.add(msg);
            }
            
            return messages;
        }
        
        if(request instanceof BulkShardRequest) {
            
            if(category != Category.FAILED_LOGIN 
                    && category != Category.MISSING_PRIVILEGES 
                    && category != Category.SG_INDEX_ATTEMPT) {
                
                return Collections.EMPTY_LIST;
            }
            
            
        }
        
        return Collections.singletonList(resolveInner(
                category, 
                effectiveUser, 
                sgAdmin, 
                initiatingUser, 
                remoteAddress, 
                action, 
                privilege, 
                origin, 
                request,
                headers,
                task,
                resolver, 
                cs, 
                settings, 
                withDetails, 
                exception));
    }
    

    private static AuditMessage resolveInner(final Category category,
            final String effectiveUser,
            final Boolean sgAdmin,
            final String initiatingUser,
            final TransportAddress remoteAddress,
            final String action,
            final String priv,
            final Origin origin, 
            final Object request,
            final Map<String, String> headers,
            final Task task,
            final IndexNameExpressionResolver resolver, 
            final ClusterService cs,
            final Settings settings,
            final boolean withDetails,
            final Throwable exception)  {

        final AuditMessage msg = new AuditMessage(category, cs, origin);
        msg.addInitiatingUser(initiatingUser);
        msg.addEffectiveUser(effectiveUser);
        msg.addRemoteAddress(remoteAddress);
        msg.addAction(action);
        msg.addRequestType(request.getClass().getSimpleName());
        
        if(sgAdmin != null) {
            msg.addIsAdminDn(sgAdmin);
        }
        
        msg.addException(exception);
        msg.addPrivilege(priv);
        msg.addTransportHeaders(headers);
        
        if(task != null) {
            msg.addTaskId(task.getId());
            if(task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                msg.addTaskParentId(task.getParentTaskId().toString());
            }
        }
        
        //attempt to resolve indices/types/id/source 
        if (request instanceof MultiGetRequest.Item) {
            final MultiGetRequest.Item item = (MultiGetRequest.Item) request;
            final String[] indices = arrayOrEmpty(item.indices());
            final String type = item.type();
            final String id = item.id();
            msg.addType(type);
            msg.addId(id);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof CreateIndexRequest) {
            final CreateIndexRequest cir = (CreateIndexRequest) request;
            final String[] indices = arrayOrEmpty(cir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof DeleteIndexRequest) {
            final DeleteIndexRequest dir = (DeleteIndexRequest) request;
            final String[] indices = arrayOrEmpty(dir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof IndexRequest) {
            final IndexRequest ir = (IndexRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            final String type = ir.type();
            final String id = ir.id();
            msg.addShardId(ir.shardId());
            msg.addType(type);
            msg.addId(id);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, ir.source(), settings, true);
            }
        } else if (request instanceof DeleteRequest) {
            final DeleteRequest dr = (DeleteRequest) request;
            final String[] indices = arrayOrEmpty(dr.indices());
            final String type = dr.type();
            final String id = dr.id();
            msg.addShardId(dr.shardId());
            msg.addType(type);
            msg.addId(id);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof UpdateRequest) {
            final UpdateRequest ur = (UpdateRequest) request;
            final String[] indices = arrayOrEmpty(ur.indices());
            final String type = ur.type();
            final String id = ur.id();
            msg.addType(type);
            msg.addId(id);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
    
                if (ur.doc() != null) {
                    msg.addSource(ur.doc() == null ? null :sourceToString(ur.doc().source()));
                }
    
                if (ur.script() != null) {
                    msg.addSource(ur.script() == null ? null : XContentHelper.toString(ur.script()));
                }
            }
        } else if (request instanceof GetRequest) {
            final GetRequest gr = (GetRequest) request;
            final String[] indices = arrayOrEmpty(gr.indices());
            final String type = gr.type();
            final String id = gr.id();
            msg.addType(type);
            msg.addId(id);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof SearchRequest) {
            final SearchRequest sr = (SearchRequest) request;
            final String[] indices = arrayOrEmpty(sr.indices());
            final String[] types = arrayOrEmpty(sr.types());
            msg.addTypes(types);
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, sr.source() == null? null:sr.source().buildAsBytes(), settings, false);
            }
        } else if (request instanceof ClusterUpdateSettingsRequest) {
            if(withDetails) {
                final ClusterUpdateSettingsRequest cusr = (ClusterUpdateSettingsRequest) request;
                final Settings persistentSettings = cusr.persistentSettings();
                final Settings transientSettings = cusr.transientSettings();
                msg.addSource("persistent: "+String.valueOf(persistentSettings == null?Collections.EMPTY_MAP:persistentSettings.getAsMap())
                             +";transient: "+String.valueOf(transientSettings == null?Collections.EMPTY_MAP:transientSettings.getAsMap()));  
            }
        } else if (request instanceof ReindexRequest) {
            final ReindexRequest ir = (ReindexRequest) request;
            final String[] indices = new String[0];//arrayOrEmpty(ir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof DeleteByQueryRequest) {
            final DeleteByQueryRequest ir = (DeleteByQueryRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof UpdateByQueryRequest) {
            final UpdateByQueryRequest ir = (UpdateByQueryRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        } else if (request instanceof PutMappingRequest) {
            final PutMappingRequest pr = (PutMappingRequest) request;
            final Index ci = pr.getConcreteIndex();
            msg.addType(pr.type());
            String[] indices = new String[0];
            
            if(ci != null) {
                indices = new String[]{ci.getName()};
            }
            
            if(withDetails) {
                msg.addIndices(indices);
                msg.addResolvedIndices(indices);
                msg.addSource(pr.source());
            }
        } else if (request instanceof IndicesRequest) { //less specific
            final IndicesRequest ir = (IndicesRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            if(withDetails) {
                addIndicesSourceSafe(msg, indices, resolver, cs, null, settings, false);
            }
        }
        
        return msg;
    }

    private static void addIndicesSourceSafe(final AuditMessage msg, 
            final String[] indices, 
            final IndexNameExpressionResolver resolver, 
            final ClusterService cs, 
            final BytesReference source,
            final Settings settings,
            final boolean sourceIsSensitive) {

        final String searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        final String[] _indices = indices == null?new String[0]:indices;
        final String[] resolvedIndices = (resolver==null)?new String[0]:resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), indices);
        msg.addIndices(_indices);
        msg.addResolvedIndices(resolvedIndices);
        
        final Set<String> allIndices = new HashSet<String>(resolvedIndices.length+_indices.length);
        allIndices.addAll(Arrays.asList(_indices));
        allIndices.addAll(Arrays.asList(resolvedIndices));

        if(allIndices.contains("_all")) {
            allIndices.add("*");
        }
        
        if(sourceIsSensitive && source != null) {   
            if(!WildcardMatcher.matchAny(allIndices.toArray(new String[0]), searchguardIndex)) {
                msg.addSource(sourceToString(source));
            }
        } else if(source != null){
            msg.addSource(sourceToString(source));
        }
    }
    
    private static String sourceToString(BytesReference source) {
        
        if(source == null) {
            return "";
        }
         try {
            return XContentHelper.convertToJson(source, false, XContentType.SMILE);
        } catch (Exception e) {
            try {
                return XContentHelper.convertToJson(source, false, XContentType.JSON);
            } catch (Exception e1) {
                return e1.toString();
            }
        }
        
        
    }
    
    private static String[] arrayOrEmpty(String[] array) {
        if(array == null) {
            return new String[0];
        }
        
        if(array.length == 1 && array[0] == null) {
            return new String[0];
        }
        
        return array;
    }
}
