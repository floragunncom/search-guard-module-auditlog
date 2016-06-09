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

package com.floragunn.searchguard.auditlog.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class Cycle<T> {
    
    private int pointer = 0;
    private final List<T> list;
    
    public Cycle(T... elements) {
        
        if(elements == null || elements.length == 0) {
            throw new IllegalArgumentException();
        }
        
        list = Arrays.asList(elements);
    }
    
    public Cycle(Collection<T> elements) {
        
        if(elements == null || elements.size() == 0) {
            throw new IllegalArgumentException();
        }
        
        list = new ArrayList<T>(elements);
    }
    
    public synchronized T next() {
        if(pointer >= list.size()) {
            pointer = 0;
        }
        
        return list.get(pointer++);
    }
}
