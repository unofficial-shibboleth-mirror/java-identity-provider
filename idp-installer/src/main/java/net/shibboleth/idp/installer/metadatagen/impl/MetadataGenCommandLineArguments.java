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
package net.shibboleth.idp.installer.metadatagen.impl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.Parameter;

import net.shibboleth.idp.cli.AbstractIdPHomeAwareCommandLineArguments;

/**
 * Command line arguments for Metadata Generation.
 */
public class MetadataGenCommandLineArguments extends AbstractIdPHomeAwareCommandLineArguments {

    /** Logger. */
    private Logger log;

    /** Do we output SAML2. */
    @Parameter(names = { "+saml2", "+2", "+SAML2"} )
    @Nullable private boolean saml2;

    /** Do we NOT output SAML2. */
    @Parameter(names = { "-saml2", "-2", "-SAML2"} )
    @Nullable private boolean noSaml2;

    /** Do we output SAM1.?*/
    @Parameter(names = { "+saml1", "+1", "+SAML1"})
    @Nullable private boolean saml1;

    /** Do we output for an SP.*/
    @Parameter(names = { "+samlSP", "+sp", "+SP", "+SAMLSP"})
    @Nullable private boolean samlSP;

    /** Do we output logout.*/
    @Parameter(names = { "+logout", "+lo"})
    @Nullable private boolean logout;

    /** Do we output Artefact.*/
    @Parameter(names = { "+artefact"})
    @Nullable private boolean artefact;

    /** Do we output for an Attribute Fetch.*/
    @Parameter(names = { "+attributeFetch"})
    @Nullable private boolean attributeFetch;

    /** Certificate for (IdP) BackChannel (attribute and artefact).*/
    @Parameter(names = { "--backChannel", "-bc"})
    @Nullable private String backChannelPath;

    /** DNS name (for back channel addresses). */
    @Parameter(names = { "--DNSName", "-d"})
    @Nonnull private String dnsName = "idp.example.org";

    /** Output.*/
    @Parameter(names = { "--output", "-o"})
    @Nullable private String output;

    /** Do we output SAML2 metadata?
     * @return what.
     */
    public boolean isSaml2() {
        return saml2;
    }

    /** Do we output SAML1 metadata?
     * @return what.
     */
    public boolean isSaml1() {
        return saml1;
    }

    /** Do we output SAML SP metadata.
     * @return what.
     */
    public boolean isSamlSP() {
        return samlSP;
    }

    /** Do we output Logout metadata?
     * @return what.
     */
    public boolean isLogout() {
        return logout;
    }

    /** Do we output Artefact metadata?
     * @return what.
     */
    public boolean isArtefact() {
        return artefact;
    }

    /** Do we output Attribute Fetch metadata?
     * @return what.
     */
    public boolean isAttributeFetch() {
        return attributeFetch;
    }

    /** Where to put the data.
     * @return where
     */
    @Nullable public String getOutput() {
        return output;
    }

    /** Returns the backChannelPath.
     * @return the path.
     */
    @Nullable public String getBackChannelPath() {
        return backChannelPath;
    }

    /** Are we outputting backchannel info?
     * @return whether we are or not.
     */
    public boolean isBackChannel() {
        return backChannelPath != null;
    }

    /** Returns the dnsName.
     * @return the name.
     */
    @Nonnull public String getDnsName() {
        return dnsName;
    }

    /** {@inheritDoc}
     * We override this to add a property file of our own making for
     * the backchannel (if needed) and dnsname.
     * */
    public List<String> getPropertyFiles() {
        final List<String> parentProps = super.getPropertyFiles();
        final Properties props = new Properties(2);
        props.setProperty("idp.dnsname", getDnsName());
        if (getBackChannelPath() != null) {
            props.setProperty("idp.backchannel.cert", getBackChannelPath());
        }
        File file = null;
        try {
            file = File.createTempFile("MetadataGen", ".properties");
            file.deleteOnExit();
            try (final FileOutputStream out = new FileOutputStream(file)) {
                props.store(out, "created");
            }
        } catch (final IOException e) {
            getLog().error("Could not generate property file", e);
        }
        final List<String> result = new ArrayList<>(parentProps.size() + 1);
        result.addAll(parentProps);
        result.add(file.getAbsolutePath());
        return result;
    }

    @Override
    public synchronized Logger getLog() {
        if (log == null) {
            log = LoggerFactory.getLogger(MetadataGenCommandLineArguments.class);
        }
        return log;
    }

    // Checkstyle: CyclomaticComplexity OFF
    @Override
    public void validate() throws IllegalArgumentException {
        if (!saml2 && noSaml2) {
            saml2 = false;
        } else {
            saml2 = true;
        }
        if (artefact && backChannelPath == null) {
            throw new IllegalArgumentException("Must specify --backChannel <path> if +artefact speificied");
        }
        if (attributeFetch && backChannelPath == null) {
            throw new IllegalArgumentException("Must specify --backChannel <path> if +attributeFetch speificied");
        }
        if (backChannelPath != null && !attributeFetch && !artefact && !saml1) {
            throw new IllegalArgumentException("--backChannel <path> requires +artefact" +
                    " and/or +attributeFetch and/or +saml1");
        }
    }
    // Checkstyle: CyclomaticComplcity ON

    @Override
    public void printHelp(final PrintStream out) {
        super.printHelp(out);
        out.println(String.format("  +%-20s %s", "SAML1, +1",
                                  "Output SAML1 Metadata."));
        out.println(String.format("  -%-20s %s", "SAML2, -2",
                                  "do NOT Output SAML2 Metadata."));
        out.println(String.format("  +%-20s %s", "SP, +SAMLSP",
                                  "Output SAML2 SP Metadata."));
        out.println(String.format("  +%-20s %s", "logout",
                                  "Output Logout Metadata."));
        out.println(String.format("  +%-20s %s", "artefact",
                                  "Output SAML artefact Metadata (requires -bc),"));
        out.println(String.format("  +%-20s %s", "attributeFetch",
                                  "Output SAML attributeFetch Metadata  (requires -bc)."));
        out.println(String.format("  -%-20s %s", "bc, --backchannel <Path>",
                                  "Path to backchannel certificate"));
        out.println(String.format("  -%-20s %s", "d, --DNSName name",
                "DNS name to use in back channel addresses (default idp.example.org)"));
        out.println(String.format("  --%-20s %s", "output, -o",
                                  "Output location."));
        out.println();
    }
}
