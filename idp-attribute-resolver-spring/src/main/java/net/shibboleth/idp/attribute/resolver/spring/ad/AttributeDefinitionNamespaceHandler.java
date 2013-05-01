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

package net.shibboleth.idp.attribute.resolver.spring.ad;

import net.shibboleth.idp.attribute.resolver.spring.ad.mapped.MappedAttributeDefinitionParser;
import net.shibboleth.idp.attribute.resolver.spring.ad.mapped.SourceValueParser;
import net.shibboleth.idp.attribute.resolver.spring.ad.mapped.ValueMapParser;
import net.shibboleth.idp.spring.BaseSpringNamespaceHandler;

// TODO incomplete
/**
 * Namespace handler for {@link net.shibboleth.idp.attribute.resolver.BaseAttributeDefinition.BaseAttributeDefinition}s.
 */
public class AttributeDefinitionNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace for this handler. */
    public static final String NAMESPACE = "urn:mace:shibboleth:2.0:resolver:ad";

    /** {@inheritDoc} */
    public void init() {
        registerBeanDefinitionParser(CryptoTransientIdAttributeDefinitionParser.TYPE_NAME,
                new CryptoTransientIdAttributeDefinitionParser());
        registerBeanDefinitionParser(PrescopedAttributeDefinitionParser.TYPE_NAME,
                new PrescopedAttributeDefinitionParser());
        registerBeanDefinitionParser(PrincipalAuthenticationMethodAttributeDefinitionParser.TYPE_NAME,
                new PrincipalAuthenticationMethodAttributeDefinitionParser());
        registerBeanDefinitionParser(PrincipalNameAttributeDefinitionParser.TYPE_NAME,
                new PrincipalNameAttributeDefinitionParser());
        registerBeanDefinitionParser(RegexSplitAttributeDefinitionParser.TYPE_NAME,
                new RegexSplitAttributeDefinitionParser());
        registerBeanDefinitionParser(SAML1NameIdentifierAttributeDefinitionParser.TYPE_NAME,
                new SAML1NameIdentifierAttributeDefinitionParser());
        registerBeanDefinitionParser(SAML2NameIDAttributeDefinitionParser.TYPE_NAME,
                new SAML2NameIDAttributeDefinitionParser());
        registerBeanDefinitionParser(ScopedAttributeDefinitionParser.TYPE_NAME,
                new ScopedAttributeDefinitionParser());
        registerBeanDefinitionParser(ScriptedAttributeDefinitionParser.TYPE_NAME,
                new ScriptedAttributeDefinitionParser());
        registerBeanDefinitionParser(SimpleAttributeDefinitionParser.TYPE_NAME,
                new SimpleAttributeDefinitionParser());
        registerBeanDefinitionParser(TemplateAttributeDefinitionParser.TYPE_NAME,
                new TemplateAttributeDefinitionParser());
        registerBeanDefinitionParser(TransientIdAttributeDefinitionParser.TYPE_NAME,
                new TransientIdAttributeDefinitionParser());
        registerBeanDefinitionParser(SourceValueParser.TYPE_NAME,
                new SourceValueParser());
        registerBeanDefinitionParser(ValueMapParser.TYPE_NAME,
                new ValueMapParser());
        registerBeanDefinitionParser(MappedAttributeDefinitionParser.TYPE_NAME,
                new MappedAttributeDefinitionParser());
    }
}