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

package edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector;

import java.beans.PropertyVetoException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import com.mchange.v2.c3p0.ComboPooledDataSource;

import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.RDBMSColumnDescriptor;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.RDBMSDataConnector.DATA_TYPES;

/**
 * Spring bean definition parser for reading relational database data connector.
 */
public class RDBMSDataConnectorBeanDefinitionParser extends BaseDataConnectorBeanDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(DataConnectorNamespaceHandler.NAMESPACE, "RelationalDatabase");

    /** ContainerManagedApplication element name. */
    public static final QName CONTAINER_MANAGED_CONNECTION_ELEMENT_NAME = new QName(
            DataConnectorNamespaceHandler.NAMESPACE, "ContainerManagedConnection");

    /** ApplicationManagedApplication element name. */
    public static final QName APPLICATION_MANAGED_CONNECTION_ELEMENT_NAME = new QName(
            DataConnectorNamespaceHandler.NAMESPACE, "ApplicationManagedConnection");

    /** QueryTemplate element name. */
    public static final QName QUERY_TEMPLATE_ELEMENT_NAME = new QName(DataConnectorNamespaceHandler.NAMESPACE,
            "QueryTemplate");

    /** Column element name. */
    public static final QName COLUMN_ELEMENT_NAME = new QName(DataConnectorNamespaceHandler.NAMESPACE, "Column");

    /** Class logger. */
    private static Logger log = Logger.getLogger(RDBMSDataConnectorBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return RDBMSDataConnectorFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(String pluginId, Element pluginConfig, Map<QName, List<Element>> pluginConfigChildren,
            BeanDefinitionBuilder pluginBuilder, ParserContext parserContext) {
        super.doParse(pluginId, pluginConfig, pluginConfigChildren, pluginBuilder, parserContext);

        DataSource connectionSource = processConnectionManagement(pluginId, pluginConfigChildren, pluginBuilder);
        pluginBuilder.addPropertyValue("connectionDataSource", connectionSource);

        String queryTemplate = processesQueryTemplate(pluginId, pluginConfigChildren, pluginBuilder);
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " database query template: " + queryTemplate);
        }
        pluginBuilder.addPropertyValue("queryTemplate", queryTemplate);

        List<RDBMSColumnDescriptor> descriptors = processColumnDescriptors(pluginId, pluginConfigChildren,
                pluginBuilder);
        pluginBuilder.addPropertyValue("columnDescriptors", descriptors);

        String validationQuery = pluginConfig.getAttributeNS(null, "validationQuery");
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " database connection validation query: " + validationQuery);
        }
        pluginBuilder.addPropertyValue("connectionValidationQuery", validationQuery);

        boolean cacheResults = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null,
                "cacheResults"));
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " cache results: " + cacheResults);
        }
        pluginBuilder.addPropertyValue("cacheResults", cacheResults);

        boolean useSP = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null,
                "queryUsesStoredProcedure"));
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " query uses stored procedures: " + useSP);
        }
        pluginBuilder.addPropertyValue("queryUsesStoredProcedures", useSP);

        boolean readOnlyCtx = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null,
                "readOnlyConnection"));
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " connections are read only: " + readOnlyCtx);
        }
        pluginBuilder.addPropertyValue("readOnlyConnections", readOnlyCtx);

        String templateEngineRef = pluginConfig.getAttributeNS(null, "templateEngine");
        pluginBuilder.addPropertyReference("templateEngine", templateEngineRef);
    }

    /**
     * Processes the connection management configuraiton.
     * 
     * @param pluginId ID of this data connector
     * @param pluginConfigChildren configuration elements for this connector
     * @param pluginBuilder bean definition builder
     * 
     * @return data source built from configuration
     */
    protected DataSource processConnectionManagement(String pluginId, Map<QName, List<Element>> pluginConfigChildren,
            BeanDefinitionBuilder pluginBuilder) {
        List<Element> cmc = pluginConfigChildren.get(CONTAINER_MANAGED_CONNECTION_ELEMENT_NAME);
        if (cmc != null && cmc.get(0) != null) {
            return buildContainerManagedConnection(pluginId, cmc.get(0));
        } else {
            return buildApplicationManagedConnection(pluginId, pluginConfigChildren.get(
                    APPLICATION_MANAGED_CONNECTION_ELEMENT_NAME).get(0));
        }
    }

    /**
     * Builds a JDBC {@link DataSource} from a ContainerManagedConnection configuration element.
     * 
     * @param pluginId ID of this data connector
     * @param cmc the container managed configuration element
     * 
     * @return the built data source
     */
    protected DataSource buildContainerManagedConnection(String pluginId, Element cmc) {
        String jndiResource = cmc.getAttributeNS(null, "resourceName");
        jndiResource = DatatypeHelper.safeTrim(jndiResource);

        Hashtable<String, String> initCtxProps = buildProperties(XMLHelper.getChildElementsByTagNameNS(cmc,
                DataConnectorNamespaceHandler.NAMESPACE, "JNDIConnectionProperty"));
        try {
            InitialContext initCtx = new InitialContext(initCtxProps);
            DataSource dataSource = (DataSource) initCtx.lookup(jndiResource);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved data source for data connector " + pluginId + " from JNDI location "
                        + jndiResource + " using properties " + initCtxProps);
            }
            return dataSource;
        } catch (NamingException e) {
            String error = "Unable to retrieve data source for data connector " + pluginId + " from JNDI location "
                    + jndiResource + " using properties " + initCtxProps;
            log.error(error, e);
            return null;
        }
    }

    /**
     * Builds a JDBC {@link DataSource} from an ApplicationManagedConnection configuration element.
     * 
     * @param pluginId ID of this data connector
     * @param amc the application managed configuration element
     * 
     * @return the built data source
     */
    protected DataSource buildApplicationManagedConnection(String pluginId, Element amc) {
        ComboPooledDataSource datasource = new ComboPooledDataSource();

        String driverClass = DatatypeHelper.safeTrim(amc.getAttributeNS(null, "jdbcDriver"));
        try {
            datasource.setDriverClass(driverClass);
            datasource.setJdbcUrl(DatatypeHelper.safeTrim(amc.getAttributeNS(null, "jdbcURL")));
            datasource.setUser(DatatypeHelper.safeTrim(amc.getAttributeNS(null, "jdbcUserName")));
            datasource.setPassword(DatatypeHelper.safeTrim(amc.getAttributeNS(null, "jdbcPassword")));

            datasource.setAcquireIncrement(Integer.parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null,
                    "poolAcquireIncrement"))));
            datasource.setAcquireRetryAttempts(Integer.parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null,
                    "poolAcquireRetryAttempts"))));
            datasource.setAcquireRetryDelay(Integer.parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null,
                    "poolAcquireRetryDelay"))));
            datasource.setBreakAfterAcquireFailure(XMLHelper.getAttributeValueAsBoolean(amc.getAttributeNodeNS(null,
                    "poolBreakAfterAcquireFailure")));

            datasource.setMinPoolSize(Integer
                    .parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null, "poolMinSize"))));
            datasource.setMaxPoolSize(Integer
                    .parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null, "poolMaxSize"))));
            datasource.setMaxIdleTime(Integer.parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null,
                    "poolMaxIdleTime"))));
            datasource.setIdleConnectionTestPeriod(Integer.parseInt(DatatypeHelper.safeTrim(amc.getAttributeNS(null,
                    "poolIdleTestPeriod"))));
            if (log.isDebugEnabled()) {
                log.debug("Created application managed data source for data connector " + pluginId);
            }
            return datasource;
        } catch (PropertyVetoException e) {
            if (log.isDebugEnabled()) {
                log.error("Unable to create data source for data connector " + pluginId + " with JDBC driver class "
                        + driverClass);
            }
            return null;
        }
    }

    /**
     * Processes the QueryTemplate configuration element.
     * 
     * @param pluginId ID of this data connector
     * @param pluginConfigChildren configuration elements
     * @param pluginBuilder the bean definition builder
     * 
     * @return SQL query template
     */
    protected String processesQueryTemplate(String pluginId, Map<QName, List<Element>> pluginConfigChildren,
            BeanDefinitionBuilder pluginBuilder) {
        List<Element> queryTemplateElems = pluginConfigChildren.get(QUERY_TEMPLATE_ELEMENT_NAME);
        String queryTemplate = queryTemplateElems.get(0).getTextContent();
        if (log.isDebugEnabled()) {
            log.debug("Data connector " + pluginId + " query template: " + queryTemplate);
        }
        return queryTemplate;
    }

    /**
     * Processes the Column descriptor configuration elements.
     * 
     * @param pluginId ID of this data connector
     * @param pluginConfigChildren configuration elements
     * @param pluginBuilder the bean definition parser
     * 
     * @return result set column descriptors
     */
    protected List<RDBMSColumnDescriptor> processColumnDescriptors(String pluginId,
            Map<QName, List<Element>> pluginConfigChildren, BeanDefinitionBuilder pluginBuilder) {
        List<RDBMSColumnDescriptor> columnDescriptors = new ArrayList<RDBMSColumnDescriptor>();

        RDBMSColumnDescriptor columnDescriptor;
        String columnName;
        String attributeId;
        String dataType;
        if (pluginConfigChildren.containsKey(COLUMN_ELEMENT_NAME)) {
            for (Element columnElem : pluginConfigChildren.get(COLUMN_ELEMENT_NAME)) {
                columnName = columnElem.getAttributeNS(null, "columnName");
                attributeId = columnElem.getAttributeNS(null, "attributeID");
                dataType = columnElem.getAttributeNS(null, "type");
                columnDescriptor = new RDBMSColumnDescriptor(columnName, attributeId, DATA_TYPES.valueOf(dataType));
                columnDescriptors.add(columnDescriptor);
            }

            if (log.isDebugEnabled()) {
                log.debug("Data connector " + pluginId + " column descriptors: " + columnDescriptors);
            }
        }

        return columnDescriptors;
    }

    /**
     * Builds a hash from PropertyType elements.
     * 
     * @param propertyElements properties elements
     * 
     * @return properties extracted from elements, key is the property name.
     */
    protected Hashtable<String, String> buildProperties(List<Element> propertyElements) {
        if (propertyElements == null || propertyElements.size() < 1) {
            return null;
        }

        Hashtable<String, String> properties = new Hashtable<String, String>();

        String propName;
        String propValue;
        for (Element propertyElement : propertyElements) {
            propName = DatatypeHelper.safeTrim(propertyElement.getAttributeNS(null, "name"));
            propValue = DatatypeHelper.safeTrim(propertyElement.getAttributeNS(null, "value"));
            properties.put(propName, propValue);
        }

        return properties;
    }
}