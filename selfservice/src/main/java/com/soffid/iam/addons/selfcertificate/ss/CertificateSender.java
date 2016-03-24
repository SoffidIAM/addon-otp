package com.soffid.iam.addons.selfcertificate.ss;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateService;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateServiceHome;

import es.caib.seycon.util.Base64;

public class CertificateSender {

	public CertificateSender() {
	}
	
	public void send (HttpServletRequest req, HttpServletResponse resp,
			X509Certificate cert, X509Certificate rootCert)
			throws ServletException, IOException {
		try {
			String agent = req.getHeader("User-Agent");
			boolean isChrome = agent != null || agent.contains("Chrome"); 
			if (!isChrome)
			{
				StringBuffer b = new StringBuffer();
				b.append("-----BEGIN CERTIFICATE-----\n")
				.append(Base64.encodeBytes(cert.getEncoded()))
				.append("\n-----END CERTIFICATE-----");
				b.append("\n-----BEGIN CERTIFICATE-----\n")
						.append(Base64.encodeBytes(rootCert.getEncoded()))
						.append("\n-----END CERTIFICATE-----\n");
				ServletOutputStream out = resp.getOutputStream();
				resp.setContentType("application/x-x509-user-cert");
				resp.setContentLength(b.length());
				out.print (b.toString());
			} else {
				ServletOutputStream out = resp.getOutputStream();
				resp.setContentType("application/x-x509-user-cert");
				byte [] b = cert.getEncoded();
				resp.setContentLength(b.length);
				out.write (b);
			}
		} catch (Exception e) {
			throw new ServletException (e);
		}
	}
}
