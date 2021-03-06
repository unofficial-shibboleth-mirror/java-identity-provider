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

package net.shibboleth.idp.profile.config;

import java.time.Duration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.impl.SecureRandomIdentifierGenerationStrategy;

import org.opensaml.security.httpclient.HttpClientSecurityConfiguration;
import org.opensaml.security.x509.tls.ClientTLSValidationConfiguration;
import org.opensaml.xmlsec.DecryptionConfiguration;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.SignatureValidationConfiguration;

/** Configuration for security behavior of profiles. */
public class SecurityConfiguration {

    /** Acceptable clock skew. */
    @Nonnull private final Duration clockSkew;

    /** Generator used to generate various secure IDs (e.g., message identifiers). */
    @Nonnull private final IdentifierGenerationStrategy idGenerator;

    /** Configuration used when validating protocol message signatures. */
    @Nullable private SignatureValidationConfiguration sigValidateConfig;

    /** Configuration used when generating protocol message signatures. */
    @Nullable private SignatureSigningConfiguration sigSigningConfig;

    /** Configuration used when decrypting protocol message information. */
    @Nullable private DecryptionConfiguration decryptConfig;

    /** Configuration used when encrypting protocol message information. */
    @Nullable private EncryptionConfiguration encryptConfig;
    
    /** Configuration used when validating client TLS X509Credentials. */
    @Nullable private ClientTLSValidationConfiguration clientTLSConfig;

    /** Configuration used when executing HttpClient requests. */
    @Nullable private HttpClientSecurityConfiguration httpClientConfig;
    
    /**
     * Constructor.
     * 
     * Initializes the clock skew to 5 minutes and the identifier generator to
     * {@link SecureRandomIdentifierGenerationStrategy} using the SHA1PRNG algorithm.
     */
    public SecurityConfiguration() {
        clockSkew = Duration.ofMinutes(5);
        idGenerator = new SecureRandomIdentifierGenerationStrategy();
    }

    /**
     * Constructor.
     * 
     * @param skew the clock skew, must be greater than 0
     * @param generator the identifier generator, must not be null
     */
    public SecurityConfiguration(@Nonnull final Duration skew, @Nonnull final IdentifierGenerationStrategy generator) {
        Constraint.isNotNull(skew, "Clock skew cannot be null");
        Constraint.isFalse(skew.isNegative() || skew.isZero(), "Clock skew must be greater than 0");
        
        clockSkew = skew;
        idGenerator = Constraint.isNotNull(generator, "Identifier generator cannot be null");
    }

    /**
     * Get the acceptable clock skew.
     * 
     * @return acceptable clock skew
     */
    @Nonnull public Duration getClockSkew() {
        return clockSkew;
    }

    /**
     * Get the generator used to generate secure identifiers.
     * 
     * @return generator used to generate secure identifiers
     */
    @Nonnull public IdentifierGenerationStrategy getIdGenerator() {
        return idGenerator;
    }

    /**
     * Get the configuration used when validating protocol message signatures.
     * 
     * @return configuration used when validating protocol message signatures, or null
     */
    @Nullable public SignatureValidationConfiguration getSignatureValidationConfiguration() {
        return sigValidateConfig;
    }

    /**
     * Set the configuration used when validating protocol message signatures.
     * 
     * @param config configuration used when validating protocol message signatures, or null
     */
    public void setSignatureValidationConfiguration(@Nullable final SignatureValidationConfiguration config) {
        sigValidateConfig = config;
    }

    /**
     * Get the configuration used when generating protocol message signatures.
     * 
     * @return configuration used when generating protocol message signatures, or null
     */
    @Nullable public SignatureSigningConfiguration getSignatureSigningConfiguration() {
        return sigSigningConfig;
    }

    /**
     * Set the configuration used when generating protocol message signatures.
     * 
     * @param config configuration used when generating protocol message signatures, or null
     */
    public void setSignatureSigningConfiguration(@Nullable final SignatureSigningConfiguration config) {
        sigSigningConfig = config;
    }

    /**
     * Get the configuration used when decrypting protocol message information.
     * 
     * @return configuration used when decrypting protocol message information, or null
     */
    @Nullable public DecryptionConfiguration getDecryptionConfiguration() {
        return decryptConfig;
    }

    /**
     * Set the configuration used when decrypting protocol message information.
     * 
     * @param config configuration used when decrypting protocol message information, or null
     */
    public void setDecryptionConfiguration(@Nullable final DecryptionConfiguration config) {
        decryptConfig = config;
    }

    /**
     * Get the configuration used when encrypting protocol message information.
     * 
     * @return configuration used when encrypting protocol message information, or null
     */
    @Nullable public EncryptionConfiguration getEncryptionConfiguration() {
        return encryptConfig;
    }

    /**
     * Set the configuration used when encrypting protocol message information.
     * 
     * @param config configuration used when encrypting protocol message information, or null
     */
    public void setEncryptionConfiguration(@Nullable final EncryptionConfiguration config) {
        encryptConfig = config;
    }

    /**
     * Get the configuration used when validating client TLS X509Credentials.
     * 
     * @return configuration used when validating client TLS X509Credentials, or null
     */
    @Nullable public ClientTLSValidationConfiguration getClientTLSValidationConfiguration() {
        return clientTLSConfig;
    }

    /**
     * Set the configuration used when validating client TLS X509Credentials.
     * 
     * @param config configuration used when validating client TLS X509Credentials, or null
     */
    public void setClientTLSValidationConfiguration(final ClientTLSValidationConfiguration config) {
        clientTLSConfig = config;
    }
    
    /**
     * Get the configuration used when executing HttpClient requests.
     * 
     * @return configuration used when executing HttpClient requests, or null
     */
    @Nullable public HttpClientSecurityConfiguration getHttpClientSecurityConfiguration() {
        return httpClientConfig;
    }

    /**
     * Set the configuration used when executing HttpClient requests.
     * 
     * @param config configuration used when executing HttpClient requests, or null
     */
    public void setHttpClientSecurityConfiguration(final HttpClientSecurityConfiguration config) {
        httpClientConfig = config;
    }
}