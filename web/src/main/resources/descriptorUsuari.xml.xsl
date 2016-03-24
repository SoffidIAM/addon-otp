<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="datanode[@name='usuaris']" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />

		<finder name="rootCert" type="rootCert" >
			<ejb-finder jndi="soffid/ejb/com.soffid.iam.addons.selfcertificate.service.SelfCertificateService"
				if="${{canQuerySelfCert}}"
				method="getRootCertificate">
			</ejb-finder>
		</finder>
		
		</xsl:copy>
	</xsl:template>

	<xsl:template match="datanode[@name='usuari']" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />

			<finder name="certs" type="cert" refreshAfterCommit="true" > 
				<ejb-finder jndi="soffid/ejb/com.soffid.iam.addons.selfcertificate.service.SelfCertificateService"
					method="findByUser"
					if="${{canQuerySelfCert}}">
					<parameter>
						<xsl:attribute name="value">${instance.codi}</xsl:attribute>
					</parameter>
				</ejb-finder>
				<new-instance-bean className="com.soffid.iam.addons.selfcertificate.common.SelfCertificate"> 
				</new-instance-bean>
			</finder>
		</xsl:copy>
	</xsl:template>


	<xsl:template match="/zkib-model" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		
			<datanode name="cert">
				<ejb-handler jndi="soffid/ejb/com.soffid.iam.addons.selfcertificate.service.SelfCertificateService" >
					<xsl:attribute name="if">${instance.revoked}</xsl:attribute>
					<update-method method="revoke">
						<parameter>
							<xsl:attribute name="value">${instance}</xsl:attribute>
						</parameter>
					</update-method>
				</ejb-handler>
			</datanode>
			
			<datanode name="rootCert"></datanode>

		</xsl:copy>
	</xsl:template>


	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


</xsl:stylesheet>