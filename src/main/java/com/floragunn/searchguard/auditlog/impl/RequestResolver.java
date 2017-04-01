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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.impl.AuditMessage.AuditMessageKey;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;

public class RequestResolver {
    
    public static void resolve(final TransportRequest request, final Map<String, Object> auditInfo,
            final IndexNameExpressionResolver resolver, final Provider<ClusterService> cs, final Settings settings) throws IOException {
        
        if (request instanceof CompositeIndicesRequest) {
            resolveInner("", request, auditInfo, resolver, cs, settings);
            
            int i = 1;
            if(request instanceof BulkRequest) {

                for(DocWriteRequest ar: ((BulkRequest) request).requests()) {
                    resolveInner("_sub_"+i, ar, auditInfo, resolver, cs, settings);
                    i++;
                }
                
            } else if(request instanceof MultiGetRequest) {
                
                for(Item item: ((MultiGetRequest) request).getItems()) {
                    resolveInner("_sub_"+i, item, auditInfo, resolver, cs, settings);
                    i++;
                }
                
            } else if(request instanceof MultiSearchRequest) {
                
                for(ActionRequest ar: ((MultiSearchRequest) request).requests()) {
                    resolveInner("_sub_"+i, ar, auditInfo, resolver, cs, settings);
                    i++;
                }
                
            } else if(request instanceof MultiTermVectorsRequest) {
                
                for(ActionRequest ar: (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                    resolveInner("_sub_"+i, ar, auditInfo, resolver, cs, settings);
                    i++;
                }
                
                
            } else {
                //log.debug("Can not handle composite request of type '"+request+"' here");
            }
            
        } else {
            resolveInner("", request, auditInfo, resolver, cs, settings);
        }
    }

    private static void resolveInner(final String postfix, final Object request, final Map<String, Object> auditInfo,
            final IndexNameExpressionResolver resolver, final Provider<ClusterService> cs,
            final Settings settings) throws IOException {

        if (request instanceof MultiGetRequest.Item) {
            final MultiGetRequest.Item item = (MultiGetRequest.Item) request;
            final String[] indices = arrayOrEmpty(item.indices());
            final String type = item.type();
            final String id = item.id();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
            auditInfo.put(AuditMessageKey.TYPES+postfix, toArray(type));
            auditInfo.put(AuditMessageKey.ID+postfix, id);
        } else if (request instanceof CreateIndexRequest) {
            final CreateIndexRequest cir = (CreateIndexRequest) request;
            final String[] indices = arrayOrEmpty(cir.indices());
            final String cause = cir.cause();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
            auditInfo.put(AuditMessageKey.CAUSE+postfix, cause);
        } else if (request instanceof DeleteIndexRequest) {
            final DeleteIndexRequest dir = (DeleteIndexRequest) request;
            final String[] indices = arrayOrEmpty(dir.indices());
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
        } else if (request instanceof IndexRequest) {
            final IndexRequest ir = (IndexRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            final String type = ir.type();
            final String id = ir.id();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, ir.source(), settings, true);
            auditInfo.put(AuditMessageKey.TYPES+postfix, toArray(type));
            auditInfo.put(AuditMessageKey.ID+postfix, id);
        } else if (request instanceof DeleteRequest) {
            final DeleteRequest dr = (DeleteRequest) request;
            final String[] indices = arrayOrEmpty(dr.indices());
            final String type = dr.type();
            final String id = dr.id();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
            auditInfo.put(AuditMessageKey.TYPES+postfix, toArray(type));
            auditInfo.put(AuditMessageKey.ID+postfix, id);
        } else if (request instanceof UpdateRequest) {
            final UpdateRequest ur = (UpdateRequest) request;
            final String[] indices = arrayOrEmpty(ur.indices());
            final String type = ur.type();
            final String id = ur.id();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
            auditInfo.put(AuditMessageKey.TYPES+postfix, toArray(type));
            auditInfo.put(AuditMessageKey.ID+postfix, id);

            if (ur.doc() != null) {
                auditInfo.put(AuditMessageKey.SOURCE+postfix, ur.doc() == null ? null : XContentHelper.convertToJson(ur.doc().source(), false));
            }

            if (ur.script() != null) {
                auditInfo.put(AuditMessageKey.SOURCE+postfix, ur.script() == null ? null : XContentHelper.toString(ur.script()));
            }
        } else if (request instanceof GetRequest) {
            final GetRequest gr = (GetRequest) request;
            final String[] indices = arrayOrEmpty(gr.indices());
            final String type = gr.type();
            final String id = gr.id();
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
            auditInfo.put(AuditMessageKey.TYPES+postfix, toArray(type));
            auditInfo.put(AuditMessageKey.ID+postfix, id);
        } else if (request instanceof SearchRequest) {
            final SearchRequest sr = (SearchRequest) request;
            final String[] indices = arrayOrEmpty(sr.indices());
            final String[] types = arrayOrEmpty(sr.types());
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, sr.source() == null? null:sr.source().buildAsBytes(), settings, false);
            auditInfo.put(AuditMessageKey.TYPES+postfix, types);
        } else if (request instanceof UpdateRequest) {
            final UpdateRequest ur = (UpdateRequest) request;
            final String[] indices = arrayOrEmpty(ur.indices());
            final String id = ur.id();
            auditInfo.put(AuditMessageKey.ID+postfix, id);
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, ur.doc() == null? null: ur.doc().source(), settings, true);
        } else if (request instanceof IndicesRequest) {
            final IndicesRequest ir = (IndicesRequest) request;
            final String[] indices = arrayOrEmpty(ir.indices());
            addIndicesSourceSafe(postfix, auditInfo, indices, resolver, cs, null, settings, false);
        } else if (request instanceof ClusterUpdateSettingsRequest) {
            final ClusterUpdateSettingsRequest cusr = (ClusterUpdateSettingsRequest) request;
            final Settings persistentSettings = cusr.persistentSettings();
            final Settings transientSettings = cusr.transientSettings();
            auditInfo.put(AuditMessageKey.SOURCE+postfix, 
                    "persistent: "+String.valueOf(persistentSettings == null?Collections.EMPTY_MAP:persistentSettings.getAsMap())
                    +";transient: "+String.valueOf(transientSettings == null?Collections.EMPTY_MAP:transientSettings.getAsMap()));  
        } else {
            //we do not support this kind of request
        }
        
        if(postfix.length() > 0) {
            auditInfo.put(AuditMessageKey.INNER_CLASS+postfix, request.getClass().toString());
        }
        
        if(request instanceof CompositeIndicesRequest) {
           //auditInfo.put(AuditMessageKey.SUBREQUEST_COUNT+postfix, ((CompositeIndicesRequest) request).subRequests().size());
        } else {
           auditInfo.put(AuditMessageKey.SUBREQUEST_COUNT+postfix, null);
        }
    }

    private static void addIndicesSourceSafe(final String postfix, final Map<String, Object> auditInfo, 
            final String[] indices, 
            final IndexNameExpressionResolver resolver, 
            final Provider<ClusterService> cs, 
            final BytesReference source,
            final Settings settings,
            final boolean sourceIsSensitive) throws IOException {

        final String searchguardIndex = settings.get(ConfigConstants.SG_CONFIG_INDEX, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        final String[] _indices = indices == null?new String[0]:indices;
        final String[] resolvedIndices = (resolver==null)?new String[0]:resolver.concreteIndexNames(cs.get().state(), IndicesOptions.lenientExpandOpen(), indices);
        auditInfo.put(AuditMessageKey.RESOLVED_INDICES+postfix, resolvedIndices);
        auditInfo.put(AuditMessageKey.INDICES+postfix, _indices);
        
        final Set<String> allIndices = new HashSet<String>(resolvedIndices.length+_indices.length);
        allIndices.addAll(Arrays.asList(_indices));
        allIndices.addAll(Arrays.asList(resolvedIndices));

        if(allIndices.contains("_all")) {
            allIndices.add("*");
        }
        
        if(sourceIsSensitive && source != null) {   
            if(!WildcardMatcher.matchAny(allIndices.toArray(new String[0]), searchguardIndex)) {
                auditInfo.put(AuditMessageKey.SOURCE+postfix, XContentHelper.convertToJson(source, false));   
            }
        } else if(source != null){
            auditInfo.put(AuditMessageKey.SOURCE+postfix, XContentHelper.convertToJson(source, false));
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
    
    private static String[] toArray(String string) {
        if(string == null) {
            return new String[0];
        }
        
        return new String[]{string};
    }
}
