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

package net.shibboleth.idp.attribute.transcoding.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.AttributeDecodingException;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.EmptyAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoder;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.impl.AttributeTranscoderRegistryImpl;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Test for {@link AttributeTranscoderRegistry}.
 */
public class AttributeTranscoderRegistryTest {
    
    private AttributeTranscoderRegistryImpl registry;
    
    @BeforeMethod public void setUp() throws ComponentInitializationException {
        registry = new AttributeTranscoderRegistryImpl();
        registry.setId("test");
        
        registry.setNamingRegistry(Collections.singletonMap(
                Pair.class, (Pair p) -> "{Pair}" + p.getFirst().toString()));
        
        registry.setClassEquivalenceRegistry(Collections.singletonMap(MyPair1.class, Pair.class));
        
        final PairTranscoder transcoder = new PairTranscoder();
        
        final Map<String,Collection<Properties>> mappings = new HashMap<>();
        
        final Properties ruleset1 = new Properties();
        ruleset1.put(AttributeTranscoderRegistry.PROP_TRANSCODER, transcoder);
        ruleset1.setProperty("name", "bar");
        
        final Properties ruleset2 = new Properties();
        ruleset2.put(AttributeTranscoderRegistry.PROP_TRANSCODER, "net.shibboleth.idp.attribute.transcoding.impl.PairTranscoder");
        ruleset2.setProperty("name", "baz");
        
        mappings.put("foo", Arrays.asList(ruleset1, ruleset2));
        mappings.put("foo2", Collections.singletonList(ruleset2));
        
        registry.setTranscoderRegistry(mappings);
        
        registry.initialize();
    }
    
    @AfterMethod public void tearDown() {
        registry.destroy();
        registry = null;
    }


    // Test no mappings to encode IdPAttribute.
    @Test public void testEncodeNoMappings() throws AttributeEncodingException {
        
        Assert.assertTrue(registry.getTranscodingProperties(new IdPAttribute("frobnitz"), Pair.class).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new IdPAttribute("frobnitz"), MyPair1.class).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new IdPAttribute("foo"), MyPair2.class).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new IdPAttribute("foo"), String.class).isEmpty());
}

    // Test no reverse mappings from a Pair/String to an IdPAttribute
    @Test public void testDecodeNoMappings() throws AttributeDecodingException {
        
        Assert.assertTrue(registry.getTranscodingProperties(new Pair("foo", "value")).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new MyPair1("foo", "value")).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new MyPair2("bar", "value")).isEmpty());
        Assert.assertTrue(registry.getTranscodingProperties(new String("bar")).isEmpty());
    }
    
    @Test public void testEncodeNoValues() throws AttributeEncodingException {
        final IdPAttribute foo = new IdPAttribute("foo");
        
        final List<Pair> pairs = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(foo, Pair.class)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            pairs.add(t.encode(null, foo, Pair.class, ruleset));
        }
        
        Assert.assertEquals(pairs.size(), 2);
        
        Assert.assertEquals(pairs.get(0).getFirst(), "bar");
        Assert.assertNull(pairs.get(0).getSecond());
        
        Assert.assertEquals(pairs.get(1).getFirst(), "baz");
        Assert.assertNull(pairs.get(1).getSecond());
    }

    @Test public void testDecodeOneNoValues() throws AttributeDecodingException {
        
        final Pair bar = new Pair("bar", null);
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(bar)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, bar, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 1);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertTrue(attributes.get(0).getValues().isEmpty());
    }

    @Test public void testDecodeTwoNoValues() throws AttributeDecodingException {
        
        final Pair baz = new Pair("baz", null);
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(baz)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, baz, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 2);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertTrue(attributes.get(0).getValues().isEmpty());

        Assert.assertEquals(attributes.get(1).getId(), "foo2");
        Assert.assertTrue(attributes.get(1).getValues().isEmpty());
    }

    @Test public void testEncodeStringValues() throws AttributeEncodingException {
        final IdPAttribute foo = new IdPAttribute("foo");
        foo.setValues(Collections.singletonList(StringAttributeValue.valueOf("value")));
        
        final List<Pair> pairs = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(foo, Pair.class)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            pairs.add(t.encode(null, foo, Pair.class, ruleset));
        }
        
        Assert.assertEquals(pairs.size(), 2);
        
        Assert.assertEquals(pairs.get(0).getFirst(), "bar");
        Assert.assertEquals(pairs.get(0).getSecond(), "value");
        
        Assert.assertEquals(pairs.get(1).getFirst(), "baz");
        Assert.assertEquals(pairs.get(1).getSecond(), "value");
    }

    @Test public void testEncodeSubtypeStringValues() throws AttributeEncodingException {
        final IdPAttribute foo = new IdPAttribute("foo");
        foo.setValues(Collections.singletonList(StringAttributeValue.valueOf("value")));
        
        final List<MyPair1> pairs = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(foo, MyPair1.class)) {
            final AttributeTranscoder<MyPair1> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            pairs.add(t.encode(null, foo, MyPair1.class, ruleset));
        }
        
        Assert.assertEquals(pairs.size(), 2);
        
        Assert.assertEquals(pairs.get(0).getFirst(), "bar");
        Assert.assertEquals(pairs.get(0).getSecond(), "value");
        
        Assert.assertEquals(pairs.get(1).getFirst(), "baz");
        Assert.assertEquals(pairs.get(1).getSecond(), "value");
    }
    
    @Test public void testDecodeOneStringValues() throws AttributeDecodingException {
        
        final Pair bar = new Pair("bar", "value");
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(bar)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, bar, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 1);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertEquals(attributes.get(0).getValues().get(0).getValue(), "value");
    }
    
    @Test public void testDecodeTwoStringValues() throws AttributeDecodingException {
        
        final Pair baz = new Pair("baz", "value");
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(baz)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, baz, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 2);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertEquals(attributes.get(0).getValues().get(0).getValue(), "value");

        Assert.assertEquals(attributes.get(1).getId(), "foo2");
        Assert.assertEquals(attributes.get(1).getValues().get(0).getValue(), "value");
    }

    @Test public void testEncodeUnsupportedValues() throws AttributeEncodingException {
        final IdPAttribute foo = new IdPAttribute("foo");
        foo.setValues(Collections.singletonList(EmptyAttributeValue.ZERO_LENGTH));
        
        final List<Pair> pairs = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(foo, Pair.class)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            pairs.add(t.encode(null, foo, Pair.class, ruleset));
        }
        
        Assert.assertEquals(pairs.size(), 2);
        
        Assert.assertEquals(pairs.get(0).getFirst(), "bar");
        Assert.assertNull(pairs.get(0).getSecond());
        
        Assert.assertEquals(pairs.get(1).getFirst(), "baz");
        Assert.assertNull(pairs.get(0).getSecond());
    }
    
    @Test public void testDecodeOneUnsupportedValues() throws AttributeDecodingException {
        
        final Pair bar = new Pair("bar", 0L);
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(bar)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, bar, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 1);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertTrue(attributes.get(0).getValues().isEmpty());
    }
    
    @Test public void testDecodeTwoUnsupportedValues() throws AttributeDecodingException {
        
        final Pair baz = new Pair("baz", 0L);
        
        final List<IdPAttribute> attributes = new ArrayList<>();
        
        for (final Properties ruleset : registry.getTranscodingProperties(baz)) {
            final AttributeTranscoder<Pair> t =
                    (AttributeTranscoder) ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);            
            attributes.add(t.decode(null, baz, ruleset));
        }
        
        Assert.assertEquals(attributes.size(), 2);
        
        Assert.assertEquals(attributes.get(0).getId(), "foo");
        Assert.assertTrue(attributes.get(0).getValues().isEmpty());

        Assert.assertEquals(attributes.get(1).getId(), "foo2");
        Assert.assertTrue(attributes.get(1).getValues().isEmpty());
    }
    
    /** Marker classes to exercise subtype support. */
    
    public static class MyPair1 extends Pair {
        public MyPair1(Object one, Object two) {
            super(one, two);
        }
    }

    public static class MyPair2 extends Pair {
        public MyPair2(Object one, Object two) {
            super(one, two);
        }        
    }

}