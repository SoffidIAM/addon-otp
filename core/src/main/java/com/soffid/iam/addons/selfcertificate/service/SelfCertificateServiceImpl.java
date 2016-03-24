package com.soffid.iam.addons.selfcertificate.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.mozilla.SignedPublicKeyAndChallenge;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;
import com.soffid.iam.addons.selfcertificate.common.RootCertificate;
import com.soffid.iam.addons.selfcertificate.model.RootCertificateEntity;
import com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SelfCertificateServiceImpl extends SelfCertificateServiceBase {
    SecureRandom random = new SecureRandom();

	
	private RootCertificateEntity getCurrentRoot ()
	{
		Date lastDate = null;
		RootCertificateEntity last = null;
		for (RootCertificateEntity root: getRootCertificateEntityDao().loadAll())
		{
			if (! root.isObsolete())
			{
				if (lastDate == null || lastDate.before(root.getCreationDate()))
				{
					last = root;
					lastDate = root.getCreationDate();
				}
			}
		}
		return last;
	}
	
	private PrivateKey getPrivateKey () throws IOException
	{
		RootCertificateEntity root = getCurrentRoot ();
		if (root != null)
		{
			byte[] material = root.getPrivateKey();
			final char[] password = getKeyPassword(root);
			StringReader reader = new StringReader(new String(material, "ISO-8859-1"));
			PEMReader pemReader = new PEMReader(reader, new PasswordFinder() {
				public char[] getPassword() {
					return password;
				}
			});
			KeyPair pair = (KeyPair) pemReader.readObject();
			pemReader.close();
			return pair.getPrivate();
		}
		return null;
	}

	private char[] getKeyPassword(RootCertificateEntity root) {
		String key = "Soffid" + root.getId() +"key";
		final char[] password =  key.toCharArray();
		return password;
	}
	
	public SelfCertificateServiceImpl() {
        java.security.Security.addProvider(new BouncyCastleProvider());
	}

    private X509V3CertificateGenerator getX509Generator() throws InternalErrorException {

        long now = System.currentTimeMillis() - 1000 * 60 * 10; // 10 minutos
        long l = now + 1000L * 60L * 60L * 24L * 365L * 5L; // 5 años
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        X509Certificate rootCert = getRootCertificate();
        
        generator.setIssuerDN(rootCert.getSubjectX500Principal());
        generator.setNotAfter(new Date(l));
        generator.setNotBefore(new Date(now));
        generator.setSerialNumber(BigInteger.valueOf(now));
        generator.setSignatureAlgorithm("sha1WithRSAEncryption");
        return generator;
    }

	@Override
	protected X509Certificate handleCreate(String description, String pkcs10) throws Exception {
		Base64Encoder b64 = new Base64Encoder();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		b64.decode(pkcs10, out);
		SignedPublicKeyAndChallenge spk = new SignedPublicKeyAndChallenge(out.toByteArray());
		if (!spk.verify("BC"))
		{
			throw new InternalErrorException ("Certificate request signature verficatin has failed");
		}
		PublicKey pk = spk.getPublicKey("BC");
		X509Certificate cert = generateUserCertificate(pk, description);
        
        return cert;
	}

	private X509Certificate generateUserCertificate(PublicKey pk, String description)
			throws InternalErrorException, NoSuchProviderException,
			SignatureException, InvalidKeyException, IOException,
			CertificateEncodingException {
		RootCertificateEntity root = getCurrentRoot();
		String currentUser = Security.getCurrentUser();

		UserEntity user = getUserEntityDao().findByUserName(currentUser);
        String name = "CN=" + currentUser + ",CN=" + description +",O="+root.getOrganizationName();
        
        // Register certificate on data base
        SelfCertificateEntity entity = getSelfCertificateEntityDao().newSelfCertificateEntity();
        entity.setDescription(description);
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MONTH, root.getUserCertificateMonths());
        entity.setExpirationDate(c.getTime());
        entity.setCreationDate (new Date());
        entity.setRevoked(false);
        entity.setCertificate(new byte[] {0});
        entity.setUser(user);
        entity.setRoot(root);
        getSelfCertificateEntityDao().create(entity);

        // Now, generate the certificate
        X509V3CertificateGenerator generator = getX509Generator();
        generator.setSubjectDN(new X509Name(name));
        generator.setPublicKey(pk);
        generator.setNotAfter(entity.getExpirationDate());
        c = Calendar.getInstance();
        c.add(Calendar.MINUTE, -10);
        generator.setNotBefore(c.getTime());
        generator.setSerialNumber(new BigInteger(entity.getId().toString()));
        
        X509Certificate cert = generator.generateX509Certificate(getPrivateKey(), "BC");
        
        entity.setCertificate(cert.getEncoded());
        getSelfCertificateEntityDao().update(entity);
		return cert;
	}

	@Override
	protected List<SelfCertificate> handleFindByUser(String user)
			throws Exception {
		List<SelfCertificateEntity> list = getSelfCertificateEntityDao().findByUser(user);
		List<SelfCertificate> certs = getSelfCertificateEntityDao().toSelfCertificateList(list);
		Collections.sort(certs, new Comparator<SelfCertificate>() {
			public int compare(SelfCertificate o1, SelfCertificate o2) {
				if (o1.getCreationDate().after(o2.getCreationDate()))
					return -1;
				else if (o2.getCreationDate().after(o1.getCreationDate()))
					return +1;
				else
					return 0;
			};
		});
		return certs;
	}

	@Override
	protected SelfCertificate handleFindByCertificate(
			X509Certificate certificate) throws Exception {
		long serialNumber = certificate.getSerialNumber().longValue();
		SelfCertificateEntity selfCert = getSelfCertificateEntityDao().load(serialNumber);
		if (selfCert == null)
			return null;
		else
			return getSelfCertificateEntityDao().toSelfCertificate(selfCert);
	}

	@Override
	protected void handleRevoke(SelfCertificate cert) throws Exception {
		SelfCertificateEntity selfCert = getSelfCertificateEntityDao().load(cert.getId());
		if (selfCert != null)
		{
			if (Security.isUserInRole("selfcertificate:manage") ||
					selfCert.getUser().getUserName().equals (Security.getCurrentUser()))
			{
				selfCert.setRevoked(true);
				getSelfCertificateEntityDao().update(selfCert);
			}
		}
	}

	@Override
	protected RootCertificate handleCreateRootCertificate(com.soffid.iam.addons.selfcertificate.common.RootCertificate root) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");

        keyGen.initialize(1024, random);

        // Generar clave raiz
        KeyPair pair = keyGen.generateKeyPair();
        
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        String dn = "CN=Soffid Self-certify addon,O="+root.getOrganizationName();
        generator.setIssuerDN( new X500Principal(dn));
        generator.setSerialNumber(BigInteger.valueOf(1));
        generator.setSignatureAlgorithm("sha1WithRSAEncryption");
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, -10);
        generator.setNotBefore(c.getTime());
        generator.setNotAfter(root.getExpirationDate().getTime());
        generator.setPublicKey(pair.getPublic());
        generator.setSubjectDN(new X500Principal(dn));
        generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true) );
        X509Certificate cert = generator.generateX509Certificate(pair.getPrivate(), "BC");

        RootCertificateEntity rootEntity = getRootCertificateEntityDao().newRootCertificateEntity();
        rootEntity.setCertificate(cert.getEncoded());
        rootEntity.setCreationDate(new Date());
        rootEntity.setExpirationDate(root.getExpirationDate().getTime());
        rootEntity.setObsolete(false);
        rootEntity.setOrganizationName(root.getOrganizationName());
        rootEntity.setUserCertificateMonths(root.getUserCertificateMonths());
        rootEntity.setPrivateKey(new byte[] {0});
        getRootCertificateEntityDao().create(rootEntity);
        
        StringWriter writer = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        
		final char[] password = getKeyPassword(rootEntity);

        pemWriter.writeObject(pair.getPrivate(), "DESEDE", password, random);
        pemWriter.close();
        
        rootEntity.setPrivateKey(writer.getBuffer().toString().getBytes("UTF-8"));
        getRootCertificateEntityDao().update(rootEntity);
        
        return getRootCertificateEntityDao().toRootCertificate(rootEntity);
	}

	@Override
	protected X509Certificate handleGetRootCertificate() throws Exception {
		RootCertificateEntity root = getCurrentRoot();
		if (root == null)
			return null;
		else
			return getRootCertificateEntityDao().toRootCertificate(root).getCertificate();
	}

	@Override
	protected int handleGetUserCertificateDuration() throws Exception {
		RootCertificateEntity root = getCurrentRoot();
		return root.getUserCertificateMonths();
	}

	@Override
	protected List<SelfCertificate> handleFindMyCertificates() throws Exception {
		String user = Security.getCurrentUser();
		List<SelfCertificate> list = findByUser(user);
		for (Iterator<SelfCertificate> it = list.iterator(); it.hasNext();)
		{
			SelfCertificate cert = it.next();
			if (cert.isRevoked())
				it.remove();
		}
		return list;
	}

	@Override
	protected void handleUpdateRootCertificate(RootCertificate root)
			throws Exception {
		RootCertificateEntity rootEntity = getRootCertificateEntityDao().load(root.getId());
		if (root.isObsolete())
			rootEntity.setObsolete(true);
		rootEntity.setUserCertificateMonths(root.getUserCertificateMonths());
	}

	@Override
	protected List<RootCertificate> handleGetRootCertificates()
			throws Exception {
		List<RootCertificateEntity> entityList = getRootCertificateEntityDao().loadAll();
		List<RootCertificate> list = getRootCertificateEntityDao().toRootCertificateList(entityList);
		Collections.sort(list, new Comparator<RootCertificate>() {
			public int compare(RootCertificate o1, RootCertificate o2) {
				if (o1.getCreationDate().after(o2.getCreationDate()))
					return -1;
				else if (o2.getCreationDate().after(o1.getCreationDate()))
					return +1;
				else
					return 0;
			};
		});
		return list;
	}

	@Override
	protected byte[] handleCreatePkcs12(String description, String password)
			throws Exception {
		KeyPair keypair = generateKeyPair ();
		X509Certificate cert = generateUserCertificate(keypair.getPublic(), description);
		
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);

        X509Certificate[] chain = new X509Certificate[2];
        // first the client, then the CA certificate
        chain[0] = cert;
        chain[1] = getRootCertificate();
        
        store.setKeyEntry("mykey", keypair.getPrivate(), password.toCharArray(), chain);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, password.toCharArray());
        out.close();
        return out.toByteArray();
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
         keyGen.initialize(2048, random);
         KeyPair keypair = keyGen.generateKeyPair();
         return keypair;
    }

	
}
