package com.soffid.iam.addons.otp.web;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Image;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.service.ejb.OtpSelfService;
import com.soffid.iam.addons.otp.service.ejb.OtpSelfServiceHome;
import com.soffid.iam.api.Password;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.Wizard;

public class MyOtpHandler extends FrameHandler {
	private OtpDevice currentDevice;


	public MyOtpHandler() throws InternalErrorException {
		super();
	}

	@Override
	public void addNew() throws Exception {
		Window w = (Window) getFellow("add-window");
		w.doHighlighted();
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.setSelected(0);
		CustomField3 type = (CustomField3) w.getFellow("type");
		List<String> s  = new LinkedList<String>();
		OtpSelfService ejb = (OtpSelfService) new InitialContext().lookup(OtpSelfServiceHome.JNDI_NAME);
		for (OtpDeviceType t: ejb.findEnabledDeviceTypes()) {
			s.add(t.getValue()+":"+Labels.getLabel("com.soffid.iam.addons.otp.common.OtpDeviceType."+t.getValue()));
		}
		type.setValues(s);
		type.updateMetadata();
		type.setValue(null);
		changeDeviceType(null);
	}

	public void changeDeviceType(Event event) {
		Window w = (Window) getFellow("add-window");
		CustomField3 type = (CustomField3) w.getFellow("type");
		CustomField3 phone = (CustomField3) w.getFellow("phone");
		CustomField3 email = (CustomField3) w.getFellow("email");
		CustomField3 pin = (CustomField3) w.getFellow("pin0");
		String s = (String) type.getValue();
		OtpDeviceType t = s == null? null: OtpDeviceType.fromString(s);
		pin.setVisible(t == OtpDeviceType.PIN);
		phone.setVisible(t == OtpDeviceType.SMS);
		email.setVisible(t == OtpDeviceType.EMAIL);
	}
	
	public void addUndo(Event event) {
		Window w = (Window) getFellow("add-window");
		w.setVisible(false);
		getModel().refresh();
	}

	public void addStep2(Event event) throws InternalErrorException, NamingException {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		CustomField3 type = (CustomField3) w.getFellow("type");
		CustomField3 phone = (CustomField3) w.getFellow("phone");
		CustomField3 email = (CustomField3) w.getFellow("email");
		CustomField3 pin = (CustomField3) w.getFellow("pin0");
		if (type.attributeValidateAll() &&
				(!phone.isVisible() || phone.attributeValidateAll()) &&
				(!email.isVisible() || email.attributeValidateAll())) {
			OtpSelfService ejb = (OtpSelfService) new InitialContext().lookup(OtpSelfServiceHome.JNDI_NAME);
			if (pin.isVisible()) {
				Password p = (Password) pin.getValue(); 
				if (p == null || p.getPassword().isEmpty())
				{
					pin.setWarning(0, Labels.getLabel("common.enterValue") );
					return;
				}
				int length = 8;
				try {
					length = Integer.parseInt( ConfigurationCache.getProperty("otp.pin.length") );
				} catch (Exception e) {}
				if (p.getPassword().length() < length) {
					pin.setWarning(0, String.format("Too short. Enter at least %d digits", length));
					return;
				}
			}
			String s = (String) type.getValue();
			OtpDeviceType t = s == null? null: OtpDeviceType.fromString(s);
			currentDevice = new OtpDevice();
			currentDevice.setType(t);
			currentDevice.setPin((Password) pin.getValue());
			currentDevice.setEmail((String) email.getValue());
			currentDevice.setPhone((String) phone.getValue());
			currentDevice.setCreated(new Date());
			currentDevice = ejb.registerDevice(currentDevice);
			getModel().refresh();
			wizard.next();
			Image i = (Image) w.getFellow("image");
			if (t == OtpDeviceType.PIN) {
				w.getFellow("imageblock").setVisible(false);
				w.getFellow("smsblock").setVisible(false);
				w.getFellow("pinblock").setVisible(true);
			} else if (currentDevice.getImage() == null) {
				w.getFellow("imageblock").setVisible(false);
				w.getFellow("smsblock").setVisible(true);
				w.getFellow("pinblock").setVisible(false);
			} else {
				w.getFellow("imageblock").setVisible(true);
				w.getFellow("smsblock").setVisible(false);
				w.getFellow("pinblock").setVisible(false);
				i.setContent(currentDevice.getImage());
			}
			CustomField3 cf3 = (CustomField3) w.getFellow("pin");
			cf3.setValue("");
			cf3.focus();
		}
	}
	
	public void addStep1(Event event) throws NamingException, InternalErrorException {
		if (currentDevice != null) {
			OtpSelfService ejb = (OtpSelfService) new InitialContext().lookup(OtpSelfServiceHome.JNDI_NAME);
			ejb.cancelDevice(currentDevice);
			currentDevice = null;
			
		}
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.previous();
	}


	public void addApply(Event event) throws NamingException, InternalErrorException {
		Window w = (Window) getFellow("add-window");
		CustomField3 cf = (CustomField3) w.getFellow("pin");
		if (cf.attributeValidateAll()) {
			Password value = (Password) cf.getValue();
			OtpSelfService ejb = (OtpSelfService) new InitialContext().lookup(OtpSelfServiceHome.JNDI_NAME);
			if (value == null || value.getPassword().trim().isEmpty()) {
				cf.setWarning(null, "Enter the PIN");
			}
			else if (ejb.enableDevice(currentDevice, value.getPassword())) {
				cf.setWarning(null, null);
				getModel().refresh();
				w.setVisible(false);
			} else {
				cf.setWarning(null, "Wrong PIN");
			}
		}
	}

	@Override
	public void afterCompose() {
		super.afterCompose();
		HttpServletRequest req = (HttpServletRequest) Executions.getCurrent().getNativeRequest();
		String wizard = req.getParameter("wizard");
		if (wizard != null && isVisible()) {
			Component w = getFellow("add-window");			
			try {
				if ("totp".equals(wizard)) {
					addNew();
					CustomField3 type = (CustomField3) w.getFellow("type");
					type.setValue(OtpDeviceType.TOTP.getValue());
					changeDeviceType(null);
					addStep2(null);
				}
				if ("hotp".equals(wizard)) {
					addNew();
					CustomField3 type = (CustomField3) w.getFellow("type");
					type.setValue(OtpDeviceType.HOTP.getValue());
					changeDeviceType(null);
					addStep2(null);
				}
				if ("email".equals(wizard)) {
					addNew();
					CustomField3 type = (CustomField3) w.getFellow("type");
					type.setValue(OtpDeviceType.EMAIL.getValue());
					changeDeviceType(null);
				}
				if ("sms".equals(wizard)) {
					addNew();
					CustomField3 type = (CustomField3) w.getFellow("type");
					type.setValue(OtpDeviceType.SMS.getValue());
					changeDeviceType(null);
					addStep2(null);
				}
				if ("pin".equals(wizard)) {
					addNew();
					CustomField3 type = (CustomField3) w.getFellow("type");
					type.setValue(OtpDeviceType.PIN.getValue());
					changeDeviceType(null);
					addStep2(null);
				}
			} catch (Exception e) {
				throw new UiException(e);
			}
		}
	}
	

}
