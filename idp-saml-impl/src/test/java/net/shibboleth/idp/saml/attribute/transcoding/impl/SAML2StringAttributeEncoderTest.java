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

package net.shibboleth.idp.saml.attribute.transcoding.impl;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.annotation.Nonnull;

import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.ByteAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoder;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.impl.AttributeTranscoderRegistryImpl;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML2AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAMLAttributeTranscoder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/** {@link SAML2StringAttributeTranscoder} unit test. */
public class SAML2StringAttributeEncoderTest extends OpenSAMLInitBaseTestCase {

    private AttributeTranscoderRegistryImpl registry;

    @Nonnull private SAMLObjectBuilder<Attribute> attributeBuilder;

    @Nonnull private SAMLObjectBuilder<RequestedAttribute> reqAttributeBuilder;

    private final static String ATTR_NAME = "foo";
    private final static String ATTR_NAMEFORMAT = "Namespace";
    private final static String ATTR_FRIENDLYNAME = "friendly";
    private final static String STRING_1 = "Value The First";
    private final static String STRING_2 = "Second string the value is";

    @BeforeClass public void setUp() throws ComponentInitializationException {
        
        attributeBuilder = (SAMLObjectBuilder<Attribute>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Attribute>getBuilderOrThrow(
                        Attribute.TYPE_NAME);
        reqAttributeBuilder = (SAMLObjectBuilder<RequestedAttribute>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<RequestedAttribute>getBuilderOrThrow(
                        RequestedAttribute.TYPE_NAME);
        
        registry = new AttributeTranscoderRegistryImpl();
        registry.setId("test");
        
        registry.setNamingRegistry(Collections.singletonMap(
                Attribute.class, new AbstractSAML2AttributeTranscoder.NamingFunction()));
        
        final SAML2StringAttributeTranscoder transcoder = new SAML2StringAttributeTranscoder();
        transcoder.initialize();
        
        final Map<String,Collection<Properties>> mappings = new HashMap<>();
        
        final Properties ruleset1 = new Properties();
        ruleset1.put(AttributeTranscoderRegistry.PROP_TRANSCODER, transcoder);
        ruleset1.put(AbstractSAMLAttributeTranscoder.PROP_ENCODE_TYPE, true);
        ruleset1.setProperty(AbstractSAMLAttributeTranscoder.PROP_NAME, ATTR_NAME);
        ruleset1.setProperty(AbstractSAML2AttributeTranscoder.PROP_NAME_FORMAT, ATTR_NAMEFORMAT);
        ruleset1.setProperty(AbstractSAML2AttributeTranscoder.PROP_FRIENDLY_NAME, ATTR_FRIENDLYNAME);
        
        mappings.put(ATTR_NAME, Collections.singletonList(ruleset1));
        
        registry.setTranscoderRegistry(mappings);
        
        registry.initialize();
    }
    
    @AfterClass public void tearDown() {
        registry.destroy();
        registry = null;
    }

    @Test(expectedExceptions = {AttributeEncodingException.class,}) public void emptyEncode() throws Exception {
        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr =
                ((AttributeTranscoder<Attribute>) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER)).encode(
                        null, inputAttribute, Attribute.class, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getName(), ATTR_NAME);
        Assert.assertEquals(attr.getNameFormat(), ATTR_NAMEFORMAT);
        Assert.assertEquals(attr.getFriendlyName(), ATTR_FRIENDLYNAME);
        Assert.assertTrue(attr.getAttributeValues().isEmpty());
    }

    @Test public void emptyDecode() throws Exception {
        
        final Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr =
                ((AttributeTranscoder<Attribute>) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER)).decode(
                        null, samlAttribute, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertTrue(attr.getValues().isEmpty());
    }

    @Test(expectedExceptions = {AttributeEncodingException.class,}) public void inappropriate() throws Exception {
        final int[] intArray = {1, 2, 3, 4};
        final Collection<? extends IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}), new IdPAttributeValue<Object>() {
                    @Override
                    public Object getValue() {
                        return intArray;
                    }
                    @Override
                    public String getDisplayValue() {
                        return intArray.toString();
                    }
                });

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        ((AttributeTranscoder<Attribute>) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER)).encode(
                null, inputAttribute, Attribute.class, ruleset);
    }

    @Test public void single() throws Exception {
        final Collection<? extends IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}), new StringAttributeValue(STRING_1));

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);
        
        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr =
                ((AttributeTranscoder<Attribute>) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER)).encode(
                        null, inputAttribute, Attribute.class, ruleset);

        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getName(), ATTR_NAME);
        Assert.assertEquals(attr.getNameFormat(), ATTR_NAMEFORMAT);
        Assert.assertEquals(attr.getFriendlyName(), ATTR_FRIENDLYNAME);

        final List<XMLObject> children = attr.getOrderedChildren();

        Assert.assertEquals(children.size(), 1, "Encoding one entry");

        final XMLObject child = children.get(0);

        Assert.assertEquals(child.getElementQName(), AttributeValue.DEFAULT_ELEMENT_NAME,
                "Attribute Value not inside <AttributeValue/>");

        Assert.assertTrue(child instanceof XSString, "Child of result attribute should be a string");

        final XSString childAsString = (XSString) child;

        Assert.assertEquals(childAsString.getValue(), STRING_1);
    }

    @Test public void multi() throws Exception {
        final Collection<? extends IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}),
                        new StringAttributeValue(STRING_1),
                        new StringAttributeValue(STRING_2),
                        new ScopedStringAttributeValue(STRING_1, STRING_2));

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr =
                ((AttributeTranscoder<Attribute>) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER)).encode(
                        null, inputAttribute, Attribute.class, ruleset);

        Assert.assertNotNull(attr);

        final List<XMLObject> children = attr.getOrderedChildren();
        Assert.assertEquals(children.size(), 3, "Encoding three entries");

        for (final XMLObject child: children) {
            Assert.assertTrue(child instanceof XSString, "Child of result attribute should be a string");
            final String childAsString = ((XSString) children.get(0)).getValue();
            Assert.assertTrue(STRING_1.equals(childAsString)||STRING_2.equals(childAsString));
        }
    }

}