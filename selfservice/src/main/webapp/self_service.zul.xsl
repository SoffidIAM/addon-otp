<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:zul="http://www.zkoss.org/2005/zul">

	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="datamodel[@rootNode='root']" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
		<datamodel id="certmodel" rootNode="root" src="addon/selfcertificate/selfServiceDescriptor.xml"/>
	</xsl:template>
 
	<xsl:template match="tabbox[@id='panels']/tabs/tab[1]" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
		<tab >
			<xsl:attribute name="label">${c:l('selfcertificate.mycertificates')}</xsl:attribute>
		</tab>
	</xsl:template>
 

	<xsl:template match="tabbox[@id='panels']/tabpanels/tabpanel[1]" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
		<tabpanel id="certificates">
			<cert_tab/>
		</tabpanel>						
	</xsl:template>


	<xsl:template match="/" priority="3">
		<xsl:processing-instruction name="component">name="cert_tab" macro-uri="/addon/selfcertificate/certlist.zul"</xsl:processing-instruction>
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


</xsl:stylesheet>