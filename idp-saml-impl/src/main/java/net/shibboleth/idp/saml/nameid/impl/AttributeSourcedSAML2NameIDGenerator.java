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

package net.shibboleth.idp.saml.nameid.impl;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.XMLObjectAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.RelyingPartyIdLookupFunction;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.profile.AbstractSAML2NameIDGenerator;
import org.opensaml.saml.saml2.profile.SAML2ObjectSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.Lists;

/**
 * Generator for {@link NameID} objects based on {@link IdPAttribute} data.
 */
@ThreadSafeAfterInit
public class AttributeSourcedSAML2NameIDGenerator extends AbstractSAML2NameIDGenerator {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AttributeSourcedSAML2NameIDGenerator.class);

    /** Strategy function to lookup AttributeContext. */
    @Nonnull private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;
    
    /** Attribute(s) to use as an identifier source. */
    @Nonnull @NonnullElements private List<String> attributeSourceIds;
    
    /** Constructor. */
    public AttributeSourcedSAML2NameIDGenerator() {
        attributeContextLookupStrategy = Functions.compose(
                new ChildContextLookup<RelyingPartyContext,AttributeContext>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext,RelyingPartyContext>(RelyingPartyContext.class));
        attributeSourceIds = Collections.emptyList();
        setDefaultIdPNameQualifierLookupStrategy(new ResponderIdLookupFunction());
        setDefaultSPNameQualifierLookupStrategy(new RelyingPartyIdLookupFunction());
    }

    /**
     * Set the lookup strategy to use to locate the {@link AttributeContext}.
     * 
     * @param strategy lookup function to use
     */
    public synchronized void setAttributeContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        attributeContextLookupStrategy = Constraint.isNotNull(strategy,
                "AttributeContext lookup strategy cannot be null");
    }
    
    /**
     * Set the attribute sources to pull from.
     * 
     * @param ids   attribute IDs to pull from
     */
    public synchronized void setAttributeSourceIds(@Nonnull @NonnullElements final List<String> ids) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(ids, "Attribute ID collection cannot be null");
        
        attributeSourceIds = Lists.newArrayList(Collections2.filter(ids, Predicates.notNull()));
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (attributeSourceIds.isEmpty()) {
            throw new ComponentInitializationException("Attribute source ID list cannot be empty");
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected NameID doGenerate(@Nonnull final ProfileRequestContext profileRequestContext)
            throws SAMLException {
        
        // Check for a natively generated NameIdentifier attribute value.

        final AttributeContext attributeCtx = attributeContextLookupStrategy.apply(profileRequestContext);
        if (attributeCtx == null) {
            log.warn("Unable to locate AttributeContext");
            return null;
        }
        
        final Map<String, IdPAttribute> attributes = attributeCtx.getIdPAttributes();
        for (final String sourceId : attributeSourceIds) {
            
            final IdPAttribute attribute = attributes.get(sourceId);
            if (attribute == null) {
                continue;
            }
            
            final Set<IdPAttributeValue<?>> values = attribute.getValues();
            for (final IdPAttributeValue value : values) {
                if (value instanceof XMLObjectAttributeValue && value.getValue() instanceof NameID) {
                    if (SAML2ObjectSupport.areNameIdentifierFormatsEquivalent(getFormat(),
                            ((NameID) value.getValue()).getFormat())) {
                        log.info("Returning NameID from XMLObject-valued attribute {}", sourceId);
                        return (NameID) value.getValue();
                    } else {
                        log.debug("Attribute {} value was NameID, but Format did not match", sourceId);
                    }
                }
            }
        }
        
        // Fall into base class version which will ask us for an identifier.
        
        return super.doGenerate(profileRequestContext);
    }
    
    /** {@inheritDoc} */
    @Override
    @Nullable protected String getIdentifier(@Nonnull final ProfileRequestContext profileRequestContext)
            throws SAMLException {
        
        final AttributeContext attributeCtx = attributeContextLookupStrategy.apply(profileRequestContext);
        
        final Map<String, IdPAttribute> attributes = attributeCtx.getIdPAttributes();
        for (final String sourceId : attributeSourceIds) {
            log.debug("Checking for source attribute {}", sourceId);
            
            final IdPAttribute attribute = attributes.get(sourceId);
            if (attribute == null) {
                continue;
            }
            
            final Set<IdPAttributeValue<?>> values = attribute.getValues();
            for (final IdPAttributeValue value : values) {
                if (value instanceof ScopedStringAttributeValue) {
                    log.info("Generating NameID from Scoped String-valued attribute {}", sourceId);
                    return ((ScopedStringAttributeValue) value).getValue()
                            + '@' + ((ScopedStringAttributeValue) value).getScope(); 
                } else if (value instanceof StringAttributeValue) {
                    log.info("Generating NameID from String-valued attribute {}", sourceId);
                    return ((StringAttributeValue) value).getValue();
                } else {
                    log.info("Unrecognized attribute value type: {}", value.getClass().getName());
                }
            }
        }
        
        log.info("Attribute sources {} did not produce a usable identifier", attributeSourceIds);
        return null;
    }

}