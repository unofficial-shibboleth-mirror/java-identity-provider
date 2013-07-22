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

package net.shibboleth.idp.saml.authn;

import java.security.Principal;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnContextDecl;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

import com.google.common.base.Objects;

/** Principal based on a SAML AuthnContextDecl. */
public final class AuthnContextDeclPrincipal implements Principal {

    /** The declaration. */
    @Nonnull private final AuthnContextDecl authnContextDecl;

    /** Serialized form of declaration. */
    @Nonnull @NotEmpty private final String name;
    
    /**
     * Constructor.
     * 
     * @param decl the declaration
     * 
     * @throws MarshallingException if an error occurs marshalling the declaration into string form
     */
    public AuthnContextDeclPrincipal(@Nonnull final AuthnContextDecl decl) throws MarshallingException {
        authnContextDecl = Constraint.isNotNull(decl, "AuthnContextDeclRef cannot be null");
        name = SerializeSupport.nodeToString(Constraint.isNotNull(XMLObjectSupport.getMarshaller(decl),
                "No marshaller for AuthnContextDecl").marshall(decl));
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getName() {
        return name;
    }
    
    /**
     * Returns the value as a SAML {@link AuthnContextDecl}.
     * 
     * @return  the principal value in the form of an {@link AuthnContextDecl}
     */
    @Nonnull public AuthnContextDecl getAuthnContextDecl() {
        return authnContextDecl;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return authnContextDecl.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof AuthnContextDeclPrincipal) {
            return name.equals(((AuthnContextDeclPrincipal) other).getName());
        }

        return false;
    }

    /** {@inheritDoc} */
    public String toString() {
        return Objects.toStringHelper(this).add("authnContextDecl", name).toString();
    }
}