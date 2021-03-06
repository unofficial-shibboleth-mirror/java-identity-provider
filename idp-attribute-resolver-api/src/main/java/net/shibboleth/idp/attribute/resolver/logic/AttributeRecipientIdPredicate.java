/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.attribute.resolver.logic;

import java.util.Collection;
import java.util.function.Predicate;

import javax.annotation.Nonnull;

import net.shibboleth.idp.attribute.resolver.context.navigate.AttributeRecipientIdLookupFunction;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.logic.StrategyIndirectedPredicate;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.context.ProfileRequestContext;

/**
 * Predicate that evaluates a {@link ProfileRequestContext} by looking for an attribute recipient
 * that matches one of a designated set. The ID is obtained from a lookup function, by default from
 * a {@link net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext} child of the
 * profile request context.
 */
public class AttributeRecipientIdPredicate extends StrategyIndirectedPredicate<ProfileRequestContext,String> {

    /**
     * Constructor.
     * 
     * @param candidates hardwired set of values to check against
     */
    public AttributeRecipientIdPredicate(@Nonnull @NonnullElements final Collection<String> candidates) {
        super(new AttributeRecipientIdLookupFunction(), StringSupport.normalizeStringCollection(candidates));
    }

    /**
     * Constructor.
     * 
     * @param pred generalized predicate
     */
    public AttributeRecipientIdPredicate(@Nonnull final Predicate<String> pred) {
        super(new AttributeRecipientIdLookupFunction(), pred);
    }

}