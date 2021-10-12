<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="datanode[@name='usuari']" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />

			<finder name="otp" type="otp" refreshAfterCommit="false" > 
				<ejb-finder jndi="java:/module/OtpService-v2"
					method="findUserDevices">
					<parameter value="${{instance.userName}}" />
				</ejb-finder>
			</finder>

		</xsl:copy>
	</xsl:template>


	<xsl:template match="/zkib-model" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		
			<datanode name="otp">
				<ejb-handler jndi="java:/module/OtpService-v2">
					<delete-method method="deleteDevice">
						<parameter value="${{instance}}" />
					</delete-method>
					<update-method method="updateDevice">
						<parameter value="${{instance}}" />
					</update-method>
				</ejb-handler>
			</datanode>

		</xsl:copy>
	</xsl:template>


	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


</xsl:stylesheet>