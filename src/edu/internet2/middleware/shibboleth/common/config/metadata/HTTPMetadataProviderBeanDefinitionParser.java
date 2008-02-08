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

package edu.internet2.middleware.shibboleth.common.config.metadata;

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Spring bean definition parser for Shibboleth file backed url metadata provider definition.
 */
public class HTTPMetadataProviderBeanDefinitionParser extends BaseMetadataProviderDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(MetadataNamespaceHandler.NAMESPACE, "HTTPMetadataProvider");

    /** {@inheritDoc} */
    protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(HTTPMetadataProvider.class);
        parseCommonConfig(builder, element, parserContext);
        parseConfig(builder, element, parserContext);
        return builder.getBeanDefinition();
    }

    /**
     * Parses the configuration for this provider.
     * 
     * @param builder builder of the bean definition
     * @param element configuration element
     * @param context current parsing context
     */
    protected void parseConfig(BeanDefinitionBuilder builder, Element element, ParserContext context) {
        builder.setInitMethodName("initialize");
        builder.addPropertyReference("parserPool", "shibboleth.ParserPool");

        String metadataURL = element.getAttributeNS(null, "metadataURL");
        builder.addConstructorArg(metadataURL);

        int requestTimeout = Integer.parseInt(element.getAttributeNS(null, "requestTimeout"));
        builder.addConstructorArg(requestTimeout);

        int cacheDuration = Integer.parseInt(element.getAttributeNS(null, "cacheDuration"));
        builder.addPropertyValue("maxCacheDuration", cacheDuration);

        if (element.hasAttributeNS(null, "maintainExpiredMetadata")) {
            builder.addPropertyValue("maintainExpiredMetadata", XMLHelper.getAttributeValueAsBoolean(element
                    .getAttributeNodeNS(null, "maintainExpiredMetadata")));
        }

        // TODO basic auth credentials
    }
}