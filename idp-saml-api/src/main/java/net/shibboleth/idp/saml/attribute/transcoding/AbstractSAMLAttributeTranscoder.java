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

package net.shibboleth.idp.saml.attribute.transcoding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.AttributeDecodingException;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.transcoding.AbstractAttributeTranscoder;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for transcoders that support SAML attributes.
 * 
 * @param <AttributeType> type of object produced
 * @param <EncodedType> the type of data that can be handled by the transcoder
 */
public abstract class AbstractSAMLAttributeTranscoder<AttributeType extends SAMLObject,
        EncodedType extends IdPAttributeValue> extends AbstractAttributeTranscoder<AttributeType> {

    /** The attribute name. */
    @Nonnull @NotEmpty public static final String PROP_NAME = "name";

    /** Whether to encode the xsi:type. */
    @Nonnull @NotEmpty public static final String PROP_ENCODE_TYPE = "encodeType";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractSAMLAttributeTranscoder.class);
        
    /** {@inheritDoc} */
    @Nullable public AttributeType encode(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final IdPAttribute attribute, @Nonnull final Properties properties)
                    throws AttributeEncodingException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        Constraint.isNotNull(attribute, "Attribute to encode cannot be null");

        final String attributeId = attribute.getId();

        if (!getActivationCondition().test(profileRequestContext)) {
            log.debug("Encoder for attribute {} inactive", attributeId);
            return null;
        }
        
        log.debug("Beginning to encode attribute {}", attributeId);

        if (attribute.getValues().isEmpty()) {
            log.warn("Unable to encode {} attribute, contains no values", attributeId);
            return null;
        }

        final List<XMLObject> samlAttributeValues = new ArrayList<>();

        EncodedType attributeValue;
        XMLObject samlAttributeValue;
        for (final IdPAttributeValue o : attribute.getValues()) {
            if (o == null) {
                // filtered out upstream leave in test for sanity
                log.debug("Skipping null value of attribute {}", attributeId);
                continue;
            }

            if (!canEncodeValue(attribute, o)) {
                log.warn("Skipping value of attribute '{}'; Type {} cannot be encoded by this encoder ({}).",
                        attributeId, o.getClass().getName(), this.getClass().getName());
                continue;
            }

            attributeValue = (EncodedType) o;
            samlAttributeValue = encodeValue(profileRequestContext, attribute, properties, attributeValue);
            if (samlAttributeValue == null) {
                log.debug("Skipping empty value for attribute {}", attributeId);
            } else {
                samlAttributeValues.add(samlAttributeValue);
            }
        }

        if (samlAttributeValues.isEmpty()) {
            log.warn("Attribute {} did not contain any encodable values", attributeId);
            return null;
        }

        log.debug("Completed encoding {} values for attribute {}", samlAttributeValues.size(), attributeId);
        return buildAttribute(profileRequestContext, attribute, properties, samlAttributeValues);
    }

    /** {@inheritDoc} */
    @Nullable public IdPAttribute decode(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AttributeType input, @Nonnull final Properties properties)
                    throws AttributeDecodingException {
        
        return null;
    }

    /**
     * Function to return an XML object in string form.
     * 
     * @param object object to decode
     * 
     * @return decoded string, or null
     */
// Checkstyle: CyclomaticComplexity OFF
    @Nullable protected String getStringValue(@Nonnull final XMLObject object) {
        String retVal = null;

        if (object instanceof XSString) {

            retVal = ((XSString) object).getValue();

        } else if (object instanceof XSURI) {

            retVal = ((XSURI) object).getValue();

        } else if (object instanceof XSBoolean) {

            retVal = ((XSBoolean) object).getValue().getValue() ? "1" : "0";

        } else if (object instanceof XSInteger) {

            retVal = ((XSInteger) object).getValue().toString();

        } else if (object instanceof XSDateTime) {

            final Instant dt = ((XSDateTime) object).getValue();
            if (dt != null) {
                retVal = DOMTypeSupport.instantToString(dt);
            } else {
                retVal = null;
            }

        } else if (object instanceof XSBase64Binary) {

            retVal = ((XSBase64Binary) object).getValue();

        } else if (object instanceof XSAny) {

            final XSAny wc = (XSAny) object;
            if (wc.getUnknownAttributes().isEmpty() && wc.getUnknownXMLObjects().isEmpty()) {
                retVal = wc.getTextContent();
            } else {
                retVal = null;
            }
        }

        if (null == retVal) {
            log.info("Value of type {} could not be converted", object.getClass().toString());
        }
        return retVal;
    }
// Checkstyle: CyclomaticComplexity ON
    
    /**
     * Encodes an attribute value in to a SAML attribute value element.
     * 
     * @param profileRequestContext current profile request
     * @param attribute the attribute being encoded
     * @param properties properties to control encoding
     * @param value the value to encoder
     * 
     * @return the attribute value or null if the resulting attribute value would be empty
     * 
     * @throws AttributeEncodingException thrown if there is a problem encoding the attribute value
     */
    @Nullable protected abstract XMLObject encodeValue(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final IdPAttribute attribute, @Nonnull final Properties properties,
            @Nonnull final EncodedType value) throws AttributeEncodingException;

    /**
     * Builds a SAML attribute element from the given attribute values.
     * 
     * @param profileRequestContext current profile request
     * @param attribute the attribute being encoded
     * @param properties properties to control encoding
     * @param attributeValues the encoded values for the attribute, never null or containing null elements
     * 
     * @return the SAML attribute element
     * 
     * @throws AttributeEncodingException thrown if there is a problem constructing the SAML attribute
     */
    @Nonnull protected abstract AttributeType buildAttribute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final IdPAttribute attribute, @Nonnull final Properties properties,
            @Nonnull @NonnullElements final List<XMLObject> attributeValues) throws AttributeEncodingException;
    
    /**
     * Function to decode a single {@link XMLObject} into an {@link IdPAttributeValue}.
     * 
     * @param object the object to decode
     * 
     * @return the returned final {@link IdPAttributeValue} or null if decoding failed
     */
    @Nullable protected abstract IdPAttributeValue<?> decodeValue(@Nullable final XMLObject object);

}