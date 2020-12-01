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

package net.shibboleth.idp.attribute.resolver.spring.dc.ldap.impl;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.ldaptive.ActivePassiveConnectionStrategy;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.FilterTemplate;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.RandomConnectionStrategy;
import org.ldaptive.RoundRobinConnectionStrategy;
import org.ldaptive.SearchConnectionValidator;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchScope;
import org.ldaptive.handler.CaseChangeEntryHandler;
import org.ldaptive.handler.CaseChangeEntryHandler.CaseChange;
import org.ldaptive.handler.DnAttributeEntryHandler;
import org.ldaptive.handler.LdapEntryHandler;
import org.ldaptive.handler.SearchResultHandler;
import org.ldaptive.pool.IdlePruneStrategy;
import org.ldaptive.referral.FollowSearchReferralHandler;
import org.ldaptive.sasl.Mechanism;
import org.ldaptive.sasl.SaslConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.CertificateHostnameVerifier;
import org.ldaptive.ssl.SslConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import net.shibboleth.ext.spring.util.SpringSupport;
import net.shibboleth.idp.attribute.resolver.dc.ldap.StringAttributeValueMappingStrategy;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.ConnectionFactoryValidator;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.LDAPDataConnector;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.V2CompatibleTemplatedExecutableSearchFilterBuilder;
import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.idp.attribute.resolver.spring.dc.impl.CacheConfigParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.AttributeResolverNamespaceHandler;
import net.shibboleth.idp.profile.spring.factory.BasicX509CredentialFactoryBean;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport.ObjectType;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.XMLConstants;

/**
 * Bean definition Parser for a {@link LDAPDataConnector}. <em>Note</em> That parsing the V2 configuration will set some
 * beans with hard wired defaults. See {@link #doV2Parse(Element, ParserContext, BeanDefinitionBuilder)}.
 */
public class LDAPDataConnectorParser extends AbstractDataConnectorParser {

    /** Schema type - resolver. */
    @Nonnull public static final QName
        TYPE_NAME_RESOLVER = new QName(AttributeResolverNamespaceHandler.NAMESPACE, "LDAPDirectory");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(LDAPDataConnectorParser.class);

    /** {@inheritDoc} */
    @Override protected Class<LDAPDataConnector> getNativeBeanClass() {
        return LDAPDataConnector.class;
    }
    
    // CheckStyle: MethodLength|CyclomaticComplexity OFF
    /**
     * Parses a version 2 configuration.
     * 
     * <p>
     * The following automatically created &amp; injected beans acquire hard wired defaults:
     * </p>
     * 
     * <ul>
     * <li>search time limit defaults to 3s, overridden by the "searchTimeLimit" attribute.
     * </li>
     * <li>search size limit defaults to 1, overridden by the "maxResultSize" attribute.</li>
     * <li>search base dn default to "", overridden by the "validateDN" attribute.</li>
     * <li>search filter defaults to "(objectClass=*)", overridden by the "validateFilter"
     * attribute.</li>
     * <li>pool min size defaults to 0 if neither the attribute "poolInitialSize" nor the
     * attribute "minPoolSize" are set.</li>
     * <li>pool max size defaults to 3 if neither the attribute "poolMaxIdleSize" nor the
     * attribute "maxPoolSize" are set.</li>
     * <li>pool validation period defaults to 30m, overridden by the attribute
     * "validateTimerPeriod"</li>
     * </ul>
     * 
     * @param config LDAPDirectory containing v2 configuration
     * @param parserContext bean definition parsing context
     * @param builder to initialize
     */
    @Override protected void doV2Parse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {
        log.debug("{} Parsing XML configuration {}", getLogPrefix(), config);

        final List<Element> oldProperties = ElementSupport.getChildElementsByTagNameNS(config,
                AttributeResolverNamespaceHandler.NAMESPACE, "LDAPProperty");
        if (oldProperties != null && !oldProperties.isEmpty()) {
            // V4 Deprecation
            DeprecationSupport.warn(ObjectType.ELEMENT, "LDAPProperty", "LDAP Connector",
                    "(replacement depends on property)");
        }
        
        final V2Parser v2Parser = new V2Parser(config, getLogPrefix());

        final String searchBuilderID = v2Parser.getBeanSearchBuilderID();
        if (searchBuilderID != null) {
            builder.addPropertyReference("executableSearchBuilder", searchBuilderID);
        } else {
            final BeanDefinition def = v2Parser.createTemplateBuilder();
            if (def != null) {
                builder.addPropertyValue("executableSearchBuilder", def);
            }
        }

        final BeanDefinitionBuilder connectionFactory =
                BeanDefinitionBuilder.genericBeanDefinition(DefaultConnectionFactory.class);
        connectionFactory.addConstructorArgValue(v2Parser.createConnectionConfig(parserContext));

        final BeanDefinition pooledConnectionFactory = v2Parser.createPooledConnectionFactory(parserContext);
        if (pooledConnectionFactory != null) {
            builder.addPropertyValue("connectionFactory", pooledConnectionFactory);
        } else {
            builder.addPropertyValue("connectionFactory", connectionFactory.getBeanDefinition());
        }

        final BeanDefinition searchOperation = v2Parser.createSearchOperation();
        builder.addPropertyValue("searchOperation", searchOperation);

        final String mappingStrategyID = AttributeSupport.getAttributeValue(config, new QName("mappingStrategyRef"));
        if (mappingStrategyID != null) {
            builder.addPropertyReference("mappingStrategy", mappingStrategyID);
        } else {
            final BeanDefinition def = v2Parser.createMappingStrategy();
            if (def != null) {
                builder.addPropertyValue("mappingStrategy", def);
            }
        }

        final String validatorID = AttributeSupport.getAttributeValue(config, new QName("validatorRef"));
        if (validatorID != null) {
            builder.addPropertyReference("validator", validatorID);
        } else {
            if (pooledConnectionFactory != null) {
                builder.addPropertyValue("validator", v2Parser.createValidator(pooledConnectionFactory));
            } else {
                builder.addPropertyValue("validator", v2Parser.createValidator(connectionFactory.getBeanDefinition()));
            }
        }
        
        final String resultCacheBeanID = CacheConfigParser.getBeanResultCacheID(config);
        if (null != resultCacheBeanID) {
            builder.addPropertyReference("resultsCache", resultCacheBeanID);
        } else {
            builder.addPropertyValue("resultsCache", v2Parser.createCache(parserContext));
        }

        builder.setInitMethodName("initialize");
        builder.setDestroyMethodName("destroy");
    }

    // Checkstyle: CyclomaticComplexity|MethodLength ON

    /**
     * Utility class for parsing v2 schema configuration.
     * 
     * <em>Note</em> That parsing the V2 configuration will set some beans with hard wired defaults. See
     * {@link #doV2Parse(Element, ParserContext, BeanDefinitionBuilder)}.
     */

    protected static class V2Parser {

        /** LDAPDirectory XML element. */
        private final Element configElement;

        /** Class logger. */
        private final Logger log = LoggerFactory.getLogger(V2Parser.class);
        
        /** LogPrefix of parent. */
        private final String logPrefix;

        /**
         * Creates a new V2Parser with the supplied LDAPDirectory element.
         * 
         * @param config LDAPDirectory element
         * @param prefix the parent's log prefix
         */
        public V2Parser(@Nonnull final Element config, @Nonnull final String prefix) {
            Constraint.isNotNull(config, "LDAPDirectory element cannot be null");
            configElement = config;
            logPrefix = prefix; 
        }

        /**
         * Creates a connection config bean definition from a v2 XML configuration.
         * 
         * @param parserContext bean definition parsing context
         * @return connection config bean definition
         */
        // CheckStyle: CyclomaticComplexity|MethodLength OFF
        @Nonnull public BeanDefinition createConnectionConfig(@Nonnull final ParserContext parserContext) {
            final String url = AttributeSupport.getAttributeValue(configElement, new QName("ldapURL"));
            final String useStartTLS = AttributeSupport.getAttributeValue(configElement, new QName("useStartTLS"));
            final String principal = AttributeSupport.getAttributeValue(configElement, new QName("principal"));
            final String principalCredential =
                    AttributeSupport.getAttributeValue(configElement, new QName("principalCredential"));
            final String authenticationType =
                    AttributeSupport.getAttributeValue(configElement, new QName("authenticationType"));
            final String connectTimeout =
                    AttributeSupport.getAttributeValue(configElement, new QName("connectTimeout"));
            final String responseTimeout =
                    AttributeSupport.getAttributeValue(configElement, new QName("responseTimeout"));

            final BeanDefinitionBuilder connectionConfig =
                    BeanDefinitionBuilder.genericBeanDefinition(ConnectionConfig.class);
            connectionConfig.addPropertyValue("ldapUrl", url);
            if (useStartTLS != null) {
                connectionConfig.addPropertyValue("useStartTLS", useStartTLS);
            }
            if (connectTimeout != null) {
                connectionConfig.addPropertyValue("connectTimeout", connectTimeout);
            } else {
                connectionConfig.addPropertyValue("connectTimeout", Duration.ofSeconds(3));
            }
            if (responseTimeout != null) {
                connectionConfig.addPropertyValue("responseTimeout", responseTimeout);
            } else {
                connectionConfig.addPropertyValue("responseTimeout", Duration.ofSeconds(3));
            }
            final BeanDefinitionBuilder sslConfig = BeanDefinitionBuilder.genericBeanDefinition(SslConfig.class);
            
            final String disableHostnameVerification =
                    configElement.getAttributeNS(null, "disableHostnameVerification");
            if (disableHostnameVerification != null) {
                final BeanDefinitionBuilder verifier =
                        BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildHostnameVerifier");
                verifier.addConstructorArgValue(disableHostnameVerification);
                verifier.addConstructorArgValue(getLogPrefix());
                sslConfig.addPropertyValue("hostnameVerifier", verifier.getBeanDefinition());
            }
            
            sslConfig.addPropertyValue("credentialConfig", createCredentialConfig(parserContext));
            connectionConfig.addPropertyValue("sslConfig", sslConfig.getBeanDefinition());
            final BeanDefinitionBuilder connectionInitializer =
                    BeanDefinitionBuilder.genericBeanDefinition(BindConnectionInitializer.class);
            if (principal != null) {
                connectionInitializer.addPropertyValue("bindDn", principal);
            }
            if (principalCredential != null) {
                final BeanDefinitionBuilder credential = BeanDefinitionBuilder.genericBeanDefinition(Credential.class);
                credential.addConstructorArgValue(principalCredential);
                connectionInitializer.addPropertyValue("bindCredential", credential.getBeanDefinition());
            }
            BeanDefinition saslConfig = null;
            if (authenticationType != null) {
                // V4 Deprecation
                DeprecationSupport.warn(ObjectType.ATTRIBUTE, "authenticationType", "<LDAPDirectory>",
                    "<SASLConfig>");
                final Mechanism mechanism = Mechanism.valueOf(authenticationType);
                if ("ANONYMOUS".equals(authenticationType)) {
                    log.warn("{} Ignoring unsupported authenticationType {}. " +
                            "Do not set bind credentials for anonymous authentication", getLogPrefix(), mechanism);
                } else if ("STRONG".equals(authenticationType)) {
                    log.warn("{} Ignoring unsupported authenticationType {}.", getLogPrefix(), mechanism);
                } else if ("SIMPLE".equals(authenticationType)) {
                    log.warn("{} Ignoring unsupported authenticationType {}. " +
                            "Set bind credentials for simple authentication", getLogPrefix(), mechanism);
                } else {
                    final BeanDefinitionBuilder saslConfigBuilder =
                            BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildSaslConfig");
                    saslConfigBuilder.addConstructorArgValue(authenticationType);
                    saslConfig = saslConfigBuilder.getBeanDefinition();
                    connectionInitializer.addPropertyValue("bindSaslConfig", saslConfig);
                }
            } else {
                saslConfig = createSaslConfig();
                connectionInitializer.addPropertyValue("bindSaslConfig", saslConfig);
            }
            if (principal != null || principalCredential != null || saslConfig != null) {
                connectionConfig.addPropertyValue("connectionInitializers", connectionInitializer.getBeanDefinition());
            }
            final String connectionStrategy = AttributeSupport.getAttributeValue(
                configElement, new QName("connectionStrategy"));
            if (connectionStrategy == null) {
                connectionConfig.addPropertyValue("connectionStrategy", new ActivePassiveConnectionStrategy());
            } else {
                switch (connectionStrategy) {
                case "ROUND_ROBIN":
                    connectionConfig.addPropertyValue("connectionStrategy", new RoundRobinConnectionStrategy());
                    break;

                case "RANDOM":
                    connectionConfig.addPropertyValue("connectionStrategy", new RandomConnectionStrategy());
                    break;

                case "DEFAULT":
                    // V4 Deprecation
                    DeprecationSupport.warn(ObjectType.CONFIGURATION, "connectionStrategy=DEFAULT", "LDAP Connector",
                            "ACTIVE_PASSIVE");
                    connectionConfig.addPropertyValue("connectionStrategy", new ActivePassiveConnectionStrategy());
                    break;
                    
                default:
                    connectionConfig.addPropertyValue("connectionStrategy", new ActivePassiveConnectionStrategy());
                    break;
                }
            }

            return connectionConfig.getBeanDefinition();
        }
        // CheckStyle: CyclomaticComplexity|MethodLength ON

        /**
         * Read StartTLS trust and authentication credentials.
         * 
         * @param parserContext bean definition parsing context
         * @return credential config
         */
        @Nonnull protected BeanDefinition createCredentialConfig(@Nonnull final ParserContext parserContext) {
            final BeanDefinitionBuilder result =
                    BeanDefinitionBuilder.genericBeanDefinition(CredentialConfigFactoryBean.class);

            final List<Element> trustElements =
                    ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE,
                            "StartTLSTrustCredential");
            final String trustResource =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "trustFile"));
            if (trustResource != null) {
                if (!trustElements.isEmpty()) {
                    log.warn("{} StartTLSTrustCredential and trustFile= are incompatible.  trustFile used.",
                            getLogPrefix());
                }
                final BeanDefinitionBuilder credential =
                        BeanDefinitionBuilder.genericBeanDefinition(BasicX509CredentialFactoryBean.class);
                credential.addPropertyValue("certificateResource", trustResource);
                result.addPropertyValue("trustCredential", credential.getBeanDefinition());
            } else if (!trustElements.isEmpty()) {
                if (trustElements.size() > 1) {
                    log.warn("{} Too many StartTLSTrustCredential elements in {}; only the first has been consulted",
                            getLogPrefix(), parserContext.getReaderContext().getResource().getDescription());
                }
                result.addPropertyValue("trustCredential",
                        SpringSupport.parseCustomElement(trustElements.get(0), parserContext, result, false));
            }

            final List<Element> authElements =
                    ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE, "StartTLSAuthenticationCredential");
            final String authKey =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "authKey"));
            final String authCert =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "authCert"));

            if (authKey != null|| authCert != null) {

                if (!authElements.isEmpty()) {
                    log.warn("{} StartTLSAuthenticationCredential and"
                            + " authKey/authCert= are incompatible.  authCert/authKey used.",
                            getLogPrefix());
                }
                final BeanDefinitionBuilder authCred =
                        BeanDefinitionBuilder.genericBeanDefinition(BasicX509CredentialFactoryBean.class);
                authCred.addPropertyValue("certificateResource", authCert);
                authCred.addPropertyValue("privateKeyResource", authKey);
                authCred.addPropertyValue("privateKeyPassword",
                                           AttributeSupport.getAttributeValue(configElement, null, "authKeyPassword"));


                result.addPropertyValue("authCredential", authCred.getBeanDefinition());

            } else if (!authElements.isEmpty()) {
                if (authElements.size() > 1) {
                    log.warn("{} Too many StartTLSAuthenticationCredential elements in {};"
                            + " only the first has been consulted", getLogPrefix(), 
                            parserContext.getReaderContext().getResource().getDescription());
                }
                result.addPropertyValue("authCredential", SpringSupport
                        .parseCustomElement(authElements.get(0), parserContext, result, false));
            }

            return result.getBeanDefinition();
        }
        
        /**
         * Get the textual content of the &lt;FilterTemplate&gt;.
         * 
         * We have to look in two places and warn appropriately.
         * @return the filter or null.
         */
        @Nullable private String getFilterText() {
            final List<Element> filterElements = ElementSupport.getChildElementsByTagNameNS(configElement,
                    AttributeResolverNamespaceHandler.NAMESPACE, "FilterTemplate");
            
            final String filter;
            if (!filterElements.isEmpty()) {
                if (filterElements.size() > 1) {
                    log.warn("{} only one <FilterTemplate> can be specified; only the first has been consulted",
                            getLogPrefix());
                }
                filter = StringSupport.trimOrNull(filterElements.get(0).getTextContent().trim());
            } else {
                filter = null;
            }
            return filter;
        }

        /**
         * Get the bean ID of an externally defined search builder.
         * 
         * @return search builder bean ID
         */
        @Nullable public String getBeanSearchBuilderID() {
            return AttributeSupport.getAttributeValue(configElement, null, "executableSearchBuilderRef");
        }
        
        /**
         * Construct the definition of the template driven search builder.
         * 
         * @return the bean definition for the template search builder.
         */
        @Nonnull public BeanDefinition createTemplateBuilder() {
            final BeanDefinitionBuilder templateBuilder = BeanDefinitionBuilder.genericBeanDefinition(
                    V2CompatibleTemplatedExecutableSearchFilterBuilder.class);
            templateBuilder.setInitMethodName("initialize");

            String velocityEngineRef = StringSupport.trimOrNull(configElement.getAttribute("templateEngine"));
            if (null == velocityEngineRef) {
                velocityEngineRef = "shibboleth.VelocityEngine";
            }
            templateBuilder.addPropertyReference("velocityEngine", velocityEngineRef);

            templateBuilder.addPropertyValue("v2Compatibility", true);

            templateBuilder.addPropertyValue("templateText", getFilterText());

            return templateBuilder.getBeanDefinition();
        }

        /**
         * Creates a new search operation bean definition from a v2 XML configuration.
         *
         * @return search operation bean definition
         */
        // CheckStyle: CyclomaticComplexity|MethodLength OFF
        @Nonnull public BeanDefinition createSearchOperation() {
            final String baseDn = AttributeSupport.getAttributeValue(configElement, new QName("baseDN"));
            final String searchScope = AttributeSupport.getAttributeValue(configElement, new QName("searchScope"));
            final String derefAliases = AttributeSupport.getAttributeValue(configElement, new QName("derefAliases"));
            final String followReferrals =
                    AttributeSupport.getAttributeValue(configElement, new QName("followReferrals"));
            final String searchTimeLimit =
                    AttributeSupport.getAttributeValue(configElement, new QName("searchTimeLimit"));
            final String maxResultSize = AttributeSupport.getAttributeValue(configElement, new QName("maxResultSize"));
            final String lowercaseAttributeNames =
                    AttributeSupport.getAttributeValue(configElement, new QName("lowercaseAttributeNames"));

            final BeanDefinitionBuilder searchRequest =
                    BeanDefinitionBuilder.genericBeanDefinition(SearchRequest.class);
            if (baseDn != null) {
                searchRequest.addPropertyValue("baseDn", baseDn);
            }
            if (searchScope != null) {
                searchRequest.addPropertyValue("searchScope", searchScope);
            }
            if (derefAliases != null) {
                searchRequest.addPropertyValue("derefAliases", derefAliases);
            }

            final BeanDefinitionBuilder searchOperation =
                    BeanDefinitionBuilder.genericBeanDefinition(SearchOperation.class);
            if (followReferrals != null) {
                final BeanDefinitionBuilder handler =
                    BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildReferralHandlers");
                handler.addConstructorArgValue(followReferrals);
                searchOperation.addPropertyValue("searchResultHandlers", handler.getBeanDefinition());
            }
            if (searchTimeLimit != null) {
                searchRequest.addPropertyValue("timeLimit", searchTimeLimit);
            } else {
                searchRequest.addPropertyValue("timeLimit", Duration.ofSeconds(3));
            }
            if (maxResultSize != null) {
                searchRequest.addPropertyValue("sizeLimit", maxResultSize);
            } else {
                searchRequest.addPropertyValue("sizeLimit", 1);
            }

            final BeanDefinitionBuilder handlers =
                    BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildSearchEntryHandlers");
            handlers.addConstructorArgValue(lowercaseAttributeNames);
            searchOperation.addPropertyValue("entryHandlers", handlers.getBeanDefinition());

            final List<Element> returnAttrsElements = ElementSupport.getChildElementsByTagNameNS(configElement, 
                    AttributeResolverNamespaceHandler.NAMESPACE, "ReturnAttributes");
            
            if (!returnAttrsElements.isEmpty()) {
                if (returnAttrsElements.size() > 1) {
                    log.warn("{} Only one <ReturnAttributes> element can be specified; "+
                            "only the first has been consulted.", getLogPrefix());
                }
                final Element returnAttrsElement = returnAttrsElements.get(0);
                
                final BeanDefinitionBuilder returnAttrs =
                        BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildStringList");
                returnAttrs.addConstructorArgValue(ElementSupport.getElementContentAsString(returnAttrsElement));
                searchRequest.addPropertyValue("returnAttributes", returnAttrs.getBeanDefinition());
            }

            final List<Element> binaryAttrsElements = ElementSupport.getChildElementsByTagNameNS(configElement,
              AttributeResolverNamespaceHandler.NAMESPACE, "BinaryAttributes");

            if (!binaryAttrsElements.isEmpty()) {
                if (binaryAttrsElements.size() > 1) {
                    log.warn("{} Only one <BinaryAttributes> element can be specified; "+
                      "only the first has been consulted.", getLogPrefix());
                }
                final Element binaryAttrsElement = binaryAttrsElements.get(0);

                final BeanDefinitionBuilder binaryAttrs =
                  BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildStringList");
                binaryAttrs.addConstructorArgValue(ElementSupport.getElementContentAsString(binaryAttrsElement));
                searchRequest.addPropertyValue("binaryAttributes", binaryAttrs.getBeanDefinition());
            }

            searchOperation.addPropertyValue("request", searchRequest.getBeanDefinition());
            return searchOperation.getBeanDefinition();
        }
        // CheckStyle: CyclomaticComplexity|MethodLength ON

        /** Get the Pool configuration &lt;ConnectionPool&gt; element contents, warning if there is more than one.
         * @return the &lt;ConnectionPool&gt; or null if there isn't one.
         */
        @Nullable Element getConnectionPoolElement() {
            final List<Element> poolConfigElements =
                    ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE, "ConnectionPool");
            if (poolConfigElements.isEmpty()) {
                return null;
            }
            if (poolConfigElements.size() > 1) {
                log.warn("{} Only one <ConnectionPool> should be specified; only the first has been consulted.",
                        getLogPrefix());
            }

            return poolConfigElements.get(0);
        }
        
        // CheckStyle: CyclomaticComplexity ON

        /**
         * Creates a new pooled connection factory bean definition from a v2 XML configuration.
         *
         * @param parserContext bean definition parsing context
         * @return pooled connection factory bean definition
         */
        // CheckStyle: MethodLength OFF
        @Nullable public BeanDefinition createPooledConnectionFactory(@Nonnull final ParserContext parserContext) {

            final Element poolConfigElement = getConnectionPoolElement();
            if (null == poolConfigElement) {
                return null;
            }
            
            if (poolConfigElement.hasAttributeNS(null, "blockWhenEmpty")) {
                // V4 Deprecation
                DeprecationSupport.warn(ObjectType.ATTRIBUTE, "blockWhenEmpty", "<ConnectionPool>",
                        "(none), will be ignored");
            }
            
            final String blockWaitTime =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("blockWaitTime"));
            final String expirationTime =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("expirationTime"));

            final BeanDefinitionBuilder connectionFactory =
                    BeanDefinitionBuilder.genericBeanDefinition(PooledConnectionFactory.class);
            connectionFactory.addPropertyValue("name", "resolver-pool");
            connectionFactory.addPropertyValue("connectionConfig", createConnectionConfig(parserContext));
            if (blockWaitTime != null) {
                connectionFactory.addPropertyValue("blockWaitTime", blockWaitTime);
            }
            if (expirationTime != null) {
                final BeanDefinitionBuilder strategy =
                        BeanDefinitionBuilder.genericBeanDefinition(IdlePruneStrategy.class);
                strategy.addConstructorArgValue(expirationTime);
                connectionFactory.addPropertyValue("pruneStrategy", strategy.getBeanDefinition());
            }

            final String minPoolSize = AttributeSupport.getAttributeValue(poolConfigElement, new QName("minPoolSize"));
            final String maxPoolSize = AttributeSupport.getAttributeValue(poolConfigElement, new QName("maxPoolSize"));
            final String validatePeriodically =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validatePeriodically"));

            if (minPoolSize == null) {
                connectionFactory.addPropertyValue("minPoolSize", 0);
            } else {
                connectionFactory.addPropertyValue("minPoolSize", minPoolSize);
            }
            if (maxPoolSize == null) {
                connectionFactory.addPropertyValue("maxPoolSize", 3);
            } else {
                connectionFactory.addPropertyValue("maxPoolSize", maxPoolSize);
            }
            if (validatePeriodically != null) {
                connectionFactory.addPropertyValue("validatePeriodically", validatePeriodically);
            }

            final BeanDefinitionBuilder validator =
                    BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildSearchValidator");
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateDN")));
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateFilter")));
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateTimerPeriod")));
            connectionFactory.addPropertyValue("validator", validator.getBeanDefinition());

            final String failFastInitialize =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("failFastInitialize"));
            if (failFastInitialize != null) {
                // V4 Deprecation
                DeprecationSupport.warnOnce(ObjectType.ATTRIBUTE, "failfastInitialize (on a ConnectionPool element)", 
                        null, "failfastInitialize (on a DataConnector)");
                connectionFactory.addPropertyValue("failFastInitialize", failFastInitialize);
            }
            connectionFactory.setInitMethodName("initialize");
            return connectionFactory.getBeanDefinition();
        }

        // CheckStyle: MethodLength ON

        /**
         * Creates a new sasl config bean definition from a v2 XML configuration.
         *
         * @return sasl config bean definition
         */
        //CheckStyle: CyclomaticComplexity OFF
        @Nullable protected BeanDefinition createSaslConfig() {
            final List<Element> saslConfigElements = ElementSupport.getChildElementsByTagNameNS(configElement,
                    AttributeResolverNamespaceHandler.NAMESPACE, "SASLConfig");

            if (saslConfigElements.isEmpty()) {
                return null;
            } else if (saslConfigElements.size() > 1) {
                log.warn("{} Only one <SASLConfig> element can be specified; "+
                        "only the first has been consulted.", getLogPrefix());
            }
            final Element saslConfigElement = saslConfigElements.get(0);
            final String mechanism = AttributeSupport.getAttributeValue(saslConfigElement, new QName("mechanism"));
            final String authorizationId = AttributeSupport.getAttributeValue(
                    saslConfigElement, new QName("authorizationId"));
            final String realm = AttributeSupport.getAttributeValue(saslConfigElement, new QName("realm"));
            final List<Element> saslProperties = ElementSupport.getChildElementsByTagNameNS(saslConfigElement,
                    AttributeResolverNamespaceHandler.NAMESPACE, "SASLProperty");

            final BeanDefinitionBuilder saslConfig = BeanDefinitionBuilder.genericBeanDefinition(SaslConfig.class);
            saslConfig.addPropertyValue("mechanism", mechanism);
            if (authorizationId != null) {
                saslConfig.addPropertyValue("authorizationId", authorizationId);
            }
            if (realm != null) {
                saslConfig.addPropertyValue("realm", realm);
            }

            if (!saslProperties.isEmpty()) {
                for (final Element property : saslProperties) {
                    final String name = AttributeSupport.getAttributeValue(property, null, "name");
                    final String value = AttributeSupport.getAttributeValue(property, null, "value");
                    if ("javax.security.sasl.qop".equals(name)) {
                        final String[] splitValues = value.split(",");
                        final String[] values = new String[splitValues.length];
                        for (int i = 0; i < splitValues.length; i++) {
                            if ("auth".equalsIgnoreCase(splitValues[i].trim())) {
                                values[i] = "AUTH";
                            } else if ("auth-int".equalsIgnoreCase(splitValues[i].trim())) {
                                values[i] = "AUTH_INT";
                            } else if ("auth-conf".equalsIgnoreCase(splitValues[i].trim())) {
                                values[i] = "AUTH_CONF";
                            } else {
                                values[i] = splitValues[i].trim();
                            }
                        }
                        saslConfig.addPropertyValue("qualityOfProtection", values);
                    } else if ("javax.security.sasl.strength".equals(name)) {
                        final String[] splitValues = value.split(",");
                        final String[] values = new String[splitValues.length];
                        for (int i = 0; i < splitValues.length; i++) {
                            values[i] = splitValues[i].trim();
                        }
                        saslConfig.addPropertyValue("securityStrength", values);
                    } else if ("javax.security.sasl.server.authentication".equals(name)) {
                        saslConfig.addPropertyValue("mutualAuthentication", value);
                    }
                }
            }

            return saslConfig.getBeanDefinition();
        }
        //CheckStyle: CyclomaticComplexity ON

        /**
         * Create the result mapping strategy. See {@link net.shibboleth.idp.attribute.resolver.dc.MappingStrategy}.
         * 
         * @return mapping strategy
         */
        @Nullable public BeanDefinition createMappingStrategy() {

            final BeanDefinitionBuilder mapper =
                    BeanDefinitionBuilder.genericBeanDefinition(StringAttributeValueMappingStrategy.class);
            final List<Element> columns = ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE, "Column");

            if (!columns.isEmpty()) {
                final ManagedMap<String, String> renamingMap = new ManagedMap<>();
                for (final Element column : columns) {
                    final String columnName = AttributeSupport.getAttributeValue(column, null, "columnName");
                    final String attributeId = AttributeSupport.getAttributeValue(column, null, "attributeID");
                    if (columnName != null && attributeId != null) {
                        renamingMap.put(columnName, attributeId);
                    }
                }
                mapper.addPropertyValue("resultRenamingMap", renamingMap);
            }

            final String noResultIsError =
                    AttributeSupport.getAttributeValue(configElement, new QName("noResultIsError"));
            if (noResultIsError != null) {
                mapper.addPropertyValue("noResultAnError", SpringSupport.getStringValueAsBoolean(noResultIsError));
            }

            final String multipleResultsIsError =
                    AttributeSupport.getAttributeValue(configElement, new QName("multipleResultsIsError"));
            if (multipleResultsIsError != null) {
                mapper.addPropertyValue("multipleResultsAnError", multipleResultsIsError);
            }
            return mapper.getBeanDefinition();
        }

        /**
         * Create the validator. See {@link net.shibboleth.idp.attribute.resolver.dc.Validator}.
         * 
         * @param connectionFactory to provide to the validator
         * 
         * @return validator
         */
        @Nullable public BeanDefinition createValidator(final BeanDefinition connectionFactory) {

            final BeanDefinitionBuilder validator =
                    BeanDefinitionBuilder.genericBeanDefinition(ConnectionFactoryValidator.class);

            validator.addPropertyValue("connectionFactory", connectionFactory);
            return validator.getBeanDefinition();
        }

        /**
         * Create a results cache bean definition. See {@link CacheConfigParser}.
         * 
         * @param parserContext bean parser context
         * 
         * @return results cache bean definition
         */
        @Nullable public BeanDefinition createCache(@Nonnull final ParserContext parserContext) {
            final CacheConfigParser parser = new CacheConfigParser(configElement);
            return parser.createCache(parserContext);
        }
        
        /** The parent's log prefix.
         * @return the log prefix.  Set up in the constructor.
         */
        @Nonnull String getLogPrefix() {
            return logPrefix;
        }

        /**
         * Converts the supplied value to a list of strings delimited by {@link XMLConstants#LIST_DELIMITERS} and comma.
         * 
         * @param value to convert to a list
         * 
         * @return list of strings
         */
        @Nonnull public static List<String> buildStringList(final String value) {
            return StringSupport.stringToList(value, XMLConstants.LIST_DELIMITERS + ",");
        }

        /**
         * Returns a search validator.
         *
         * @param validateDN baseDN to search on
         * @param validateFilter to search with
         * @param validatePeriod period over which to validate connection when periodic validation in enabled
         *
         * @return  search validator or null
         */
        @Nullable public static SearchConnectionValidator buildSearchValidator(
                @Nullable final String validateDN,
                @Nullable final String validateFilter,
                @Nullable final String validatePeriod) {
            final SearchRequest searchRequest = new SearchRequest();
            searchRequest.setReturnAttributes("1.1");
            searchRequest.setSearchScope(SearchScope.OBJECT);
            searchRequest.setSizeLimit(1);
            if (validateDN != null) {
                searchRequest.setBaseDn(validateDN);
            } else {
                searchRequest.setBaseDn("");
            }
            final FilterTemplate searchFilter = new FilterTemplate();
            if (validateFilter != null) {
                searchFilter.setFilter(validateFilter);
            } else {
                searchFilter.setFilter("(objectClass=*)");
            }
            searchRequest.setFilter(searchFilter);
            final SearchConnectionValidator validator = new SearchConnectionValidator();
            if (validatePeriod != null) {
                validator.setValidatePeriod(Duration.parse(validatePeriod));
            }
            validator.setSearchRequest(searchRequest);
            return validator;
        }
        
        @Nullable public static CertificateHostnameVerifier buildHostnameVerifier(
                @Nullable final String disableHostnameVerification, @Nullable final String logPrefix) {
            if (disableHostnameVerification != null && Boolean.valueOf(disableHostnameVerification)) {
                LoggerFactory.getLogger(LDAPDataConnectorParser.class).warn(
                        "{} TLS server certificate name checking is disabled!", logPrefix);
                return new AllowAnyHostnameVerifier();
            }
            return null;
        }

        /**
         * Factory method for handling spring property replacement. Adds a {@link DnAttributeEntryHandler} by default.
         * Adds a {@link CaseChangeEntryHandler} if lowercaseAttributeNames is true. 
         * 
         * @param lowercaseAttributeNames boolean string value
         * @return list of search entry handlers
         */
        @Nonnull public static List<LdapEntryHandler> buildSearchEntryHandlers(
                @Nullable final String lowercaseAttributeNames) {
            final List<LdapEntryHandler> handlers = new ArrayList<>();
            handlers.add(new DnAttributeEntryHandler());
            if (Boolean.valueOf(lowercaseAttributeNames)) {
                final CaseChangeEntryHandler entryHandler = new CaseChangeEntryHandler();
                entryHandler.setAttributeNameCaseChange(CaseChange.LOWER);
                handlers.add(entryHandler);
            }
            return handlers;
        }

        /**
         * Returns search referral handlers or null if followReferrals is false.
         *
         * @param followReferrals whether to create a search referral handler
         *
         * @return  search result handlers or null
         */
        @Nonnull public static List<SearchResultHandler> buildReferralHandlers(
                @Nullable final String followReferrals) {
            final List<SearchResultHandler> handlers = new ArrayList<>();
            if (followReferrals != null && Boolean.valueOf(followReferrals)) {
                handlers.add(new FollowSearchReferralHandler());
                return handlers;
            }
            return null;
        }

        /**
         * Returns a SASL configuration for the supplied mechanism.
         *
         * @param mechanism SASL mechanism
         *
         * @return  SASL config
         */
        @Nonnull public static SaslConfig buildSaslConfig(@Nonnull final String mechanism) {
            final SaslConfig config = new SaslConfig();
            config.setMechanism(Mechanism.valueOf(mechanism));
            return config;
        }
    }
}
