/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.common.attribute.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.SAMLSecurityPolicy;
import org.opensaml.saml1.core.AttributeDesignator;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.xml.XMLObjectBuilderFactory;

import edu.internet2.middleware.shibboleth.common.attribute.Attribute;
import edu.internet2.middleware.shibboleth.common.attribute.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.SAML1AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilterContext;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.BasicFilterContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.ResolutionContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;

/**
 * SAML 1 Attribute Authority.
 */
public class SAML1AttributeAuthorityImpl implements SAML1AttributeAuthority {

    /** Class logger. */
    private static Logger log = Logger.getLogger(SAML1AttributeAuthorityImpl.class);

    /** For building attribute statements. */
    private SAMLObjectBuilder<AttributeStatement> statementBuilder;

    /** For building attributes. */
    private SAMLObjectBuilder<org.opensaml.saml1.core.Attribute> attributeBuilder;

    /** Attribute resolver. */
    private AttributeResolver attributeResolver;

    /** Security policy. */
    private SAMLSecurityPolicy securityPolicy;

    /** Relying party configuration. */
    private RelyingPartyConfiguration relyingPartyConfiguration;

    /** To determine releasable attributes. */
    private FilteringEngine filteringEngine;

    /**
     * This creates a new attribute authority.
     * 
     * @param ar The attribute resolver to set.
     * @param sp The security policy to set.
     * @param rpc The relying party configuration to set.
     * @param fe The filtering engine to set.
     */
    public SAML1AttributeAuthorityImpl(AttributeResolver ar, SAMLSecurityPolicy sp, RelyingPartyConfiguration rpc,
            FilteringEngine fe) {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        statementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attributeBuilder = (SAMLObjectBuilder<org.opensaml.saml1.core.Attribute>) builderFactory
                .getBuilder(org.opensaml.saml1.core.Attribute.DEFAULT_ELEMENT_NAME);

        attributeResolver = ar;
        securityPolicy = sp;
        relyingPartyConfiguration = rpc;
        filteringEngine = fe;
    }

    /**
     * Gets the attribute resolver.
     * 
     * @return Returns the attributeResolver.
     */
    public AttributeResolver getAttributeResolver() {
        return attributeResolver;
    }

    /**
     * Gets the filtering engine.
     * 
     * @return Returns the filteringEngine.
     */
    public FilteringEngine getFilteringEngine() {
        return filteringEngine;
    }

    /**
     * Gets the relying party configuration.
     * 
     * @return Returns the relyingPartyConfiguration.
     */
    public RelyingPartyConfiguration getRelyingPartyConfiguration() {
        return relyingPartyConfiguration;
    }

    /**
     * Gets the security policy.
     * 
     * @return Returns the securityPolicy.
     */
    public SAMLSecurityPolicy getSecurityPolicy() {
        return securityPolicy;
    }

    /**
     * Creates a <code>ResolutionContext</code> that can be passed to
     * {@link #performAttributeQuery(AttributeQuery, ResolutionContext, FilterContext)}.
     * 
     * @param principal to create resolution context with
     * @return <code>ResolutionContext</code>
     */
    public ResolutionContext createResolutionContext(String principal) {
        return attributeResolver.createResolutionContext(principal, securityPolicy.getIssuer().toString());
    }

    /**
     * Creates a <code>FilterContext</code> that can be passed to
     * {@link #performAttributeQuery(AttributeQuery, ResolutionContext, FilterContext)}.
     * 
     * @param resolutionContext to create filter context with
     * @param authenticationMethod to create filter context with
     * @return <code>FilterContext</code>
     */
    public FilterContext createFilterContext(ResolutionContext resolutionContext, String authenticationMethod) {
        String filterPrincipal = resolutionContext.getPrincipalName();
        String filterRequester = securityPolicy.getIssuerMetadata().getID();
        String filterIssuer = relyingPartyConfiguration.getProviderID();
        return new BasicFilterContext(filterRequester, filterIssuer, filterPrincipal, authenticationMethod,
                new HashMap<String, Attribute>());
    }

    /** {@inheritDoc} */
    public AttributeStatement performAttributeQuery(AttributeQuery query, ResolutionContext resolutionContext,
            FilterContext filterContext) throws AttributeResolutionException, FilteringException {
        // get attributes from the message
        List<AttributeDesignator> queryAttributes = query.getAttributeDesignators();
        Set<String> queryAttributeIds = getAttributeIds(queryAttributes);
        if (log.isDebugEnabled()) {
            log.debug("query message contains the following attributes: " + queryAttributeIds);
        }
        // TODO get attributes from the metadata
        Set<String> metadataAttributeIds = null;

        // union the attribute id sets
        Set<String> attributeIds = new HashSet<String>(queryAttributeIds);
        attributeIds.addAll(metadataAttributeIds);

        // get resolved attributes from the resolver
        Map<String, Attribute> resolvedAttributes = getResolvedAttributes(resolutionContext, attributeIds);

        // filter attributes
        filterContext.getAttributes().clear();
        filterContext.getAttributes().putAll(resolvedAttributes);
        Map<String, Attribute> filteredAttributes = filteringEngine.filterAttributes(filterContext);

        // encode attributes
        List<org.opensaml.saml1.core.Attribute> encodedAttributes = encodeAttributes(filteredAttributes);

        // return attribute statement
        return buildAttributeStatement(encodedAttributes);
    }

    /** {@inheritDoc} */
    public AttributeStatement performAttributeQuery(String entity, NameIdentifier subject) {
        // TODO not implemented yet
        return null;
    }

    /** {@inheritDoc} */
    public String getAttributeIDBySAMLAttribute(AttributeDesignator attribute) {
        // TODO not implemented yet
        return attribute.getAttributeName();
    }

    /** {@inheritDoc} */
    public AttributeDesignator getSAMLAttributeByAttributeID(String id) {
        AttributeDesignator attribute = attributeBuilder.buildObject();
        attribute.setAttributeName(id);
        return attribute;
    }

    /**
     * This parses the attribute ids from the supplied list of attributes.
     * 
     * @param attributes <code>List</code>
     * @return <code>Set</code> of attribute ids
     */
    private Set<String> getAttributeIds(List<AttributeDesignator> attributes) {
        final Set<String> attributeIds = new HashSet<String>();
        for (AttributeDesignator a : attributes) {
            String attrId = getAttributeIDBySAMLAttribute(a);
            attributeIds.add(attrId);
        }
        return attributeIds;
    }

    /**
     * This resolves the supplied attribute names using the supplied resolution context.
     * 
     * @param context <code>ResolutionContext</code>
     * @param releasedAttributes <code>Set</code>
     * @return <code>Map</code> of attribute ID to attribute
     * @throws AttributeResolutionException if an attribute cannot be resolved
     */
    private Map<String, Attribute> getResolvedAttributes(ResolutionContext context, Set<String> releasedAttributes)
            throws AttributeResolutionException {
        // call Attribute resolver
        Map<String, Attribute> resolvedAttributes = attributeResolver.resolveAttributes(releasedAttributes, context);
        if (log.isDebugEnabled()) {
            log.debug("attribute resolver resolved the following attributes: " + resolvedAttributes);
        }
        return resolvedAttributes;
    }

    /**
     * This encodes the supplied attributes with that attribute's SAML1 encoder.
     * 
     * @param resolvedAttributes <code>Map</code>
     * @return <code>List</code> of core attributes
     */
    private List<org.opensaml.saml1.core.Attribute> encodeAttributes(Map<String, Attribute> resolvedAttributes) {
        // encode attributes
        List<org.opensaml.saml1.core.Attribute> encodedAttributes = new ArrayList<org.opensaml.saml1.core.Attribute>();

        for (Map.Entry<String, Attribute> entry : resolvedAttributes.entrySet()) {
            AttributeEncoder<org.opensaml.saml1.core.Attribute> enc = entry.getValue().getEncoderByCategory(
                    SAML1AttributeEncoder.CATEGORY);
            encodedAttributes.add(enc.encode(entry.getValue()));
        }
        if (log.isDebugEnabled()) {
            log.debug("attribute encoder encoded the following attributes: " + encodedAttributes);
        }
        return encodedAttributes;
    }

    /**
     * This builds the attribute statement for this SAML request.
     * 
     * @param encodedAttributes <code>List</code> of attributes
     * @return <code>AttributeStatement</code>
     */
    private AttributeStatement buildAttributeStatement(List<org.opensaml.saml1.core.Attribute> encodedAttributes) {
        AttributeStatement statement = statementBuilder.buildObject();
        statement.getAttributes().addAll(encodedAttributes);
        return statement;
    }
}
