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

import static org.testng.Assert.assertEquals;

import java.io.IOException;

import org.testng.annotations.Test;

import net.shibboleth.ext.spring.cli.AbstractCommandLine;

/**
 *
 */
@SuppressWarnings("javadoc")
public class MetadataGenTest {
    @Test(enabled = false) public void test() throws IOException {
        assertEquals(MetadataGenCLI.runMain(
                    new String[] { 
                            "--home", "H:/Downloads/idp",
                            "--verbose",
                            "+saml1",
                            "--backChannel", "H:/Downloads/idp/credentials/idp-backchannel.crt",
                            "+attributeFetch",
                            "--output", "C:/Users/rdw/Desktop/logs/Md.txt"}),
                AbstractCommandLine.RC_OK);
    }

}
