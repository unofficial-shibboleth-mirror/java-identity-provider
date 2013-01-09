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

package net.shibboleth.idp.attribute.resolver.impl.dc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.Attribute;
import net.shibboleth.idp.attribute.AttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.AttributeResolutionException;
import net.shibboleth.idp.attribute.resolver.BaseDataConnector;
import net.shibboleth.idp.attribute.resolver.ResolvedAttributeDefinition;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Optional;

/**
 * A data connector that generates a unique ID by computing the SHA-1 hash of a given attribute value, the entity ID of
 * the inbound message issuer, and a provided salt.
 */
public class ComputedIDDataConnector extends BaseDataConnector {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ComputedIDDataConnector.class);

    /** ID of the attribute generated by this data connector. */
    private String generatedAttribute;

    /** ID of the attribute whose first value is used when generating the computed ID. */
    private String sourceAttribute;

    /** Salt used when computing the ID. */
    private byte[] salt;

    /** Strategy used to locate the SP EntityId given a {@link AttributeResolutionContext}. */
    // TODO(rdw) These needs to be changed when the profile handling has been finalized
    private Function<AttributeResolutionContext, String> spEntityIdStrategy;

    /**
     * Gets the salt used when computing the ID.
     * 
     * @return salt used when computing the ID
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Sets the salt used when computing the ID.
     * 
     * @param newValue used when computing the ID
     */
    public void setSalt(byte[] newValue) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        salt = newValue;
    }

    /**
     * Gets the ID of the attribute whose first value is used when generating the computed ID.
     * 
     * @return ID of the attribute whose first value is used when generating the computed ID
     */
    public String getSourceAttributeId() {
        return sourceAttribute;
    }

    /**
     * Sets the ID of the attribute whose first value is used when generating the computed ID.
     * 
     * @param newAttributeId what to set.
     */
    public void setSourceAttributeId(String newAttributeId) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        sourceAttribute = newAttributeId;
    }

    /**
     * Gets the ID of the attribute generated by this connector.
     * 
     * @return ID of the attribute generated by this connector
     */
    public String getGeneratedAttributeId() {
        return generatedAttribute;
    }

    /**
     * Sets the ID of the attribute generated by this connector.
     * 
     * @param newAttributeId what to set.
     */
    public void setGeneratedAttributeId(String newAttributeId) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        generatedAttribute = newAttributeId;
    }

    /**
     * Gets the strategy for finding the RelyingParty EntityId from the resolution context.
     * 
     * @return the required strategy.
     */
    public Function<AttributeResolutionContext, String> getSPEntityIdStrategy() {
        return spEntityIdStrategy;
    }

    /**
     * Sets the strategy for finding the RelyingPartyContext from the resolution context.
     * 
     * @param strategy to set.
     */
    public void setSPEntityIdStrategy(Function<AttributeResolutionContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        spEntityIdStrategy = strategy;
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (null == spEntityIdStrategy) {
            throw new ComponentInitializationException("Attribute definition '" + getId()
                    + "': no SP EntityId Lookup Strategy set");
        }

        if (null == salt) {
            throw new ComponentInitializationException("Attribute definition '" + getId() + "': no salt set");
        }
        
        if (salt.length < 16) {
            throw new ComponentInitializationException("Attribute definition '" + getId() + "': salt must be at least 16 bytes in size");
        }

        if (null == sourceAttribute) {
            throw new ComponentInitializationException("Attribute definition '" + getId()
                    + "': no source Attribute set");
        }

        if (null == generatedAttribute) {
            generatedAttribute = getId();
        }
    }

    /**
     * Helper function to locate the source Attribute in the dependencies.
     * 
     * @param resolutionContext the context to look in
     * @return the value, or null in any of the failure cases.
     */
     @Nullable private String resolveSourceAttribute(@Nonnull AttributeResolutionContext resolutionContext) {
        ResolvedAttributeDefinition attributeDefinition =
                resolutionContext.getResolvedAttributeDefinitions().get(getSourceAttributeId());
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (null == attributeDefinition || !attributeDefinition.getResolvedAttribute().isPresent()) {
            log.warn("Source attribute {} for connector {} was not present in dependencies", getSourceAttributeId(),
                    getId());
            return null;
        }

        final Set<AttributeValue> attributeValues = attributeDefinition.getResolvedAttribute().get().getValues();
        if (attributeValues == null || attributeValues.isEmpty()) {
            log.debug("Source attribute {} for connector {} provide no values", getSourceAttributeId(), getId());
            return null;
        }

        if (attributeValues.size() > 1) {
            log.warn("Source attribute {} for connector {} has more than one value, only the first value is used",
                    getSourceAttributeId(), getId());
        }

        final AttributeValue attributeValue = attributeValues.iterator().next();

        if (attributeValue instanceof StringAttributeValue) {
            return ((StringAttributeValue) attributeValue).getValue();
        } else {
            log.warn("Source attribute {} for connector {} was not a string type.  Not used", getSourceAttributeId(),
                    getId());
            return null;
        }
    }

    /** {@inheritDoc} */
    @Nonnull protected Optional<Map<String, Attribute>> doDataConnectorResolve(
            @Nonnull AttributeResolutionContext resolutionContext) throws AttributeResolutionException {
        
        
        String spEntityId = spEntityIdStrategy.apply(resolutionContext);
        if (spEntityId == null) {
            log.debug("Connector {} : No source SP identified, unable to compute ID", getId());
            throw new AttributeResolutionException("No SP identified");
        }

        String sourceValue = resolveSourceAttribute(resolutionContext);
        if (null == sourceValue) {
            // The message will have been logged above
            return Optional.absent();
        }

        Attribute attribute = new Attribute(getGeneratedAttributeId());

        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(spEntityId.getBytes());
            md.update((byte) '!');
            md.update(sourceValue.getBytes());
            md.update((byte) '!');

            attribute.setValues(Collections.singleton((AttributeValue) new StringAttributeValue(Base64Support.encode(
                    md.digest(salt), Base64Support.UNCHUNKED))));
        } catch (NoSuchAlgorithmException e) {
            log.error("JVM error, SHA-1 hash is not supported.");
            throw new AttributeResolutionException("SHA-1A is not supported, unable to compute ID");
        }
        return Optional.of(Collections.singletonMap(getGeneratedAttributeId(), attribute));
    }
}
