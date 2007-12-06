/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.AbstractResolutionPlugIn;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.DataConnector;

/**
 * Base class for {@link AttributeDefinition} plug-ins.
 */
public abstract class BaseAttributeDefinition extends AbstractResolutionPlugIn<BaseAttribute> implements
        AttributeDefinition {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BaseAttributeDefinition.class);

    /** Whether this attribute definition is only a dependency and thus its values should never be released. */
    private boolean dependencyOnly;

    /** Attribute encoders associated with this definition. */
    private ArrayList<AttributeEncoder> encoders;

    /** Name of the attribute from data connectors to use to populate this definition. */
    private String sourceAttributeID;

    /** Human intelligible attribute name. */
    private String displayName;

    /** Human readable description of attribute. */
    private String displayDescription;

    /**
     * Constructor.
     */
    public BaseAttributeDefinition() {
        dependencyOnly = false;
        encoders = new ArrayList<AttributeEncoder>();
    }

    /** {@inheritDoc} */
    public boolean isDependencyOnly() {
        return dependencyOnly;
    }

    /**
     * Sets whether this attribute definition is only a dependency and thus its values should never be released outside
     * the resolver.
     * 
     * @param isDependencyOnly whether this attribute definition is only a dependency
     */
    public void setDependencyOnly(boolean isDependencyOnly) {
        dependencyOnly = isDependencyOnly;
    }

    /** {@inheritDoc} */
    public List<AttributeEncoder> getAttributeEncoders() {
        return encoders;
    }

    /** {@inheritDoc} */
    public BaseAttribute resolve(ShibbolethResolutionContext resolutionContext) throws AttributeResolutionException {
        log.debug("Resolving attribute: {}", getId());
        BaseAttribute resolvedAttribute = doResolve(resolutionContext);

        if(resolvedAttribute == null){
            log.error("{} produced a null attribute, this is not allowed", getId());
            throw new AttributeResolutionException(getId() + " produced a null attribute");
        }
        
        if (getAttributeEncoders() != null) {
            resolvedAttribute.getEncoders().addAll(getAttributeEncoders());
        }

        return resolvedAttribute;
    }

    /**
     * Creates and populates the values for the resolved attribute. Implementations should *not* set, or otherwise
     * manage, the attribute encoders for the resolved attribute.
     * 
     * @param resolutionContext current attribute resolution context
     * 
     * @return resolved attribute
     * 
     * @throws AttributeResolutionException thrown if there is a problem resolving and creating the attribute
     */
    protected abstract BaseAttribute doResolve(ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException;

    /**
     * Get values from dependencies.
     * 
     * @param context resolution context
     * @return collection of values
     */
    protected Collection<Object> getValuesFromAllDependencies(ShibbolethResolutionContext context) {
        return getValuesFromAllDependencies(context, getSourceAttributeID());
    }

    /**
     * Get values from dependencies.
     * 
     * @param context resolution context
     * @param sourceAttribute ID of attribute to retrieve from dependencies
     * @return collection of values
     */
    protected Collection<Object> getValuesFromAllDependencies(ShibbolethResolutionContext context,
            String sourceAttribute) {
        List<Object> values = new ArrayList<Object>();

        for (String id : getDependencyIds()) {
            if (context.getResolvedAttributeDefinitions().containsKey(id)) {
                values.addAll(getValuesFromAttributeDependency(context, id));
            } else if (context.getResolvedDataConnectors().containsKey(id)) {
                values.addAll(getValuesFromConnectorDependency(context, id, sourceAttribute));
            }
        }

        return values;
    }

    /**
     * Get values from attribute dependencies.
     * 
     * @param context resolution context
     * @param id ID of attribute to retrieve dependencies for
     * 
     * @return collection of values
     */
    protected Collection<Object> getValuesFromAttributeDependency(ShibbolethResolutionContext context, String id) {
        List<Object> values = new ArrayList<Object>();

        AttributeDefinition definition = context.getResolvedAttributeDefinitions().get(id);
        if (definition != null) {
            try {
                BaseAttribute attribute = definition.resolve(context);
                for (Object o : attribute.getValues()) {
                    values.add(o);
                }
            } catch (AttributeResolutionException e) {
                // TODO Auto-generated catch block
            }
        }

        return values;
    }

    /**
     * Get values from data connectors.
     * 
     * @param context resolution context
     * @param id ID of attribute to retrieve dependencies for
     * @param sourceAttribute ID of attribute to retrieve from connector dependencies
     * 
     * @return collection of values
     */
    protected Collection<Object> getValuesFromConnectorDependency(ShibbolethResolutionContext context, String id,
            String sourceAttribute) {
        List<Object> values = new ArrayList<Object>();

        DataConnector connector = context.getResolvedDataConnectors().get(id);
        if (connector != null) {
            try {
                Map<String, BaseAttribute> attributes = connector.resolve(context);
                for (String attributeId : attributes.keySet()) {
                    if (attributeId != null && attributeId.equals(sourceAttribute)) {
                        for (Object o : attributes.get(attributeId).getValues()) {
                            values.add(o);
                        }
                    }
                }
            } catch (AttributeResolutionException e) {
                // TODO Auto-generated catch block
            }

        }

        return values;
    }

    /**
     * Return the source attribute. If the source attribute is null, return the definition ID.
     * 
     * @return Returns the sourceAttribute.
     */
    public String getSourceAttributeID() {
        if (sourceAttributeID != null) {
            return sourceAttributeID;
        } else {
            return getId();
        }
    }

    /**
     * Set the source attribute.
     * 
     * @param newSourceAttributeID The sourceAttribute to set.
     */
    public void setSourceAttributeID(String newSourceAttributeID) {
        sourceAttributeID = newSourceAttributeID;
    }

    /**
     * Gets the human readable description of attribute.
     * 
     * @return human readable description of attribute
     */
    public String getDisplayDescription() {
        return displayDescription;
    }

    /**
     * Gets the human readable name of the attribute.
     * 
     * @return human readable name of the attribute
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Sets the human readable description of attribute.
     * 
     * @param description human readable description of attribute
     */
    public void setDisplayDescription(String description) {
        displayDescription = description;
    }

    /**
     * Sets the human readable name of the attribute.
     * 
     * @param name human readable name of the attribute
     */
    public void setDisplayName(String name) {
        displayName = name;
    }
}