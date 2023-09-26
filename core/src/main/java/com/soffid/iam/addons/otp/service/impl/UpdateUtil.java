package com.soffid.iam.addons.otp.service.impl;

import org.apache.commons.beanutils.PropertyUtils;

import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.model.OtpDeviceEntityDao;
import com.soffid.iam.common.security.SoffidPrincipal;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class UpdateUtil {
	public static void update(OtpDeviceEntityDao dao, OtpDeviceEntity entity, AsyncRunnerService svc) throws InterruptedException {
		final SoffidPrincipal p = Security.getSoffidPrincipal();
		Thread thread = new Thread(() -> {
			Security.nestedLogin(p);
			try {
				svc.runNewTransaction(() -> {
					OtpDeviceEntity entity2 = dao.load(entity.getId());
					entity2.setFails(entity.getFails());
					entity2.setLastUsed(entity.getLastUsed());
					entity2.setLastUsedValue(entity.getLastUsedValue());
					entity2.setStatus(entity.getStatus());
					dao.update(entity2);
					return null;
				});
			} catch (InternalErrorException e) {
			} finally {
				Security.nestedLogoff();
			}
		});
		thread.start();
		thread.join();
	}
}
