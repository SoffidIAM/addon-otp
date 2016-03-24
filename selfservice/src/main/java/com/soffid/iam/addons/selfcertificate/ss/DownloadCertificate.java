package com.soffid.iam.addons.selfcertificate.ss;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateService;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateServiceHome;

import es.caib.seycon.util.Base64;

public class DownloadCertificate extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		Long id = Long.decode(req.getParameter("id"));
	
		try {
			SelfCertificateServiceHome home = (SelfCertificateServiceHome) new InitialContext()
				.lookup(SelfCertificateServiceHome.JNDI_NAME);
			SelfCertificateService svc = home.create();
			
			for (SelfCertificate self: svc.findMyCertificates())
			{
				if (id.equals (self.getId()))
				{
					X509Certificate rootCert = svc.getRootCertificate();
					new CertificateSender ().send (req, resp, self.getCertificate(), rootCert); 
				}
			}
		} catch (Exception e) {
			throw new ServletException (e);
		}
	}
}

			
