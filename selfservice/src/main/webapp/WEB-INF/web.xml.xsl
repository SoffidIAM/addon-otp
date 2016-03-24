<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:j2ee="http://java.sun.com/xml/ns/j2ee">
	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="/j2ee:web-app" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
			
			<servlet xmlns="http://java.sun.com/xml/ns/j2ee">
				<description>
					<![CDATA[Certificate generator]]>
				</description>
				<servlet-name>SelfCertificateGenerator</servlet-name>
				<servlet-class>com.soffid.iam.addons.selfcertificate.ss.GenerateCertificateServlet</servlet-class>
			</servlet>
			<servlet-mapping xmlns="http://java.sun.com/xml/ns/j2ee">
				<servlet-name>SelfCertificateGenerator</servlet-name>
				<url-pattern>/addon/selfcertificate/generate.html</url-pattern>
			</servlet-mapping>
			
			<servlet xmlns="http://java.sun.com/xml/ns/j2ee">
				<description>
					<![CDATA[Certificate downloader]]>
				</description>
				<servlet-name>DownloadCertificate</servlet-name>
				<servlet-class>com.soffid.iam.addons.selfcertificate.ss.DownloadCertificate</servlet-class>
			</servlet>
			<servlet-mapping xmlns="http://java.sun.com/xml/ns/j2ee">
				<servlet-name>DownloadCertificate</servlet-name>
				<url-pattern>/addon/selfcertificate/download</url-pattern>
			</servlet-mapping>
		</xsl:copy>
	</xsl:template>
 

	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>

</xsl:stylesheet>