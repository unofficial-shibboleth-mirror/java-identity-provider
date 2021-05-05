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

package net.shibboleth.idp.attribute.resolver.spring.impl;

import java.util.Collection;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.attribute.resolver.DataConnector;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.service.ServiceException;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * Strategy for summoning up an {@link AttributeResolverImpl} from a populated {@link ApplicationContext}. We do this by
 * finding all the configured {@link AttributeDefinition} and {@link DataConnector} beans and bunging them into the
 * Attribute Resolver which we then initialize.
 */
public class AttributeResolverServiceStrategy extends AbstractIdentifiableInitializableComponent implements
        Function<ApplicationContext,ServiceableComponent<AttributeResolver>> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AttributeResolverServiceStrategy.class);
    
    /** Whether to strip null attribute values. */
    private boolean stripNulls;

    /** Whether to attach DisplayInfo to attributes. */
    private boolean suppressDisplayInformation;
    
    /** Do we strip nulls from attribute values.
    * @return Returns whether to strip nulls from attribute values
    */
    public boolean isStripNulls() {
        return stripNulls;
    }

    /** 
     * Sets whether to strip nulls from attribute values.
     * @param doStripNulls what to set 
     */
    public void setStripNulls(final boolean doStripNulls) {
       stripNulls = doStripNulls;
    }

    /** Do we allow addition of Display Information?
     * @return whether we are suppressing
     */
    public boolean isSuppressDisplayInformation() {
       return suppressDisplayInformation;
    }

    /**
     * Set whether we suppress addition of Display Information.
     *
     * @param what true if we suppress the addition.
     */
    public void setSuppressDisplayInformation(final boolean what) {
        suppressDisplayInformation = what;
    }

    /** {@inheritDoc} */
    @Nullable public ServiceableComponent<AttributeResolver> apply(@Nullable final ApplicationContext appContext) {

        final Collection<AttributeDefinition> definitions =
                appContext.getBeansOfType(AttributeDefinition.class).values();

        final Collection<DataConnector> connectors = appContext.getBeansOfType(DataConnector.class).values();

        log.debug("Creating Attribute Resolver {} with {} Attribute Definition(s) and {} Data Connector(s)",
                getId(), definitions.size(), connectors.size());

        final AttributeResolverImpl resolver = new AttributeResolverImpl();
        resolver.setAttributeDefinitions(definitions);
        resolver.setDataConnectors(connectors);
        resolver.setId(getId());
        resolver.setStripNulls(isStripNulls());
        resolver.setSuppressDisplayInformation(isSuppressDisplayInformation());
        resolver.setApplicationContext(appContext);

        try {
            resolver.initialize();
        } catch (final ComponentInitializationException e) {
            throw new ServiceException("Unable to initialize attribute resolver for " + appContext.getDisplayName(), e);
        }
        return resolver;
    }
    
}