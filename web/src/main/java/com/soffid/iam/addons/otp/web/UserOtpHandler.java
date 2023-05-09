package com.soffid.iam.addons.otp.web;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Path;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Image;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.service.ejb.OtpSelfService;
import com.soffid.iam.addons.otp.service.ejb.OtpSelfServiceHome;
import com.soffid.iam.addons.otp.service.ejb.OtpService;
import com.soffid.iam.addons.otp.service.ejb.OtpServiceHome;
import com.soffid.iam.api.Password;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataModel;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.datamodel.DataModelCollection;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.XPathUtils;

public class UserOtpHandler extends FrameHandler {
	private OtpDevice currentDevice;
	String parentPath;
	String model;


	public UserOtpHandler() throws InternalErrorException {
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
		OtpDeviceType t = s == null || s.trim().isEmpty() ? null: OtpDeviceType.fromString(s);
		pin.setVisible(t == OtpDeviceType.PIN);
		phone.setVisible(t == OtpDeviceType.SMS);
		email.setVisible(t == OtpDeviceType.EMAIL);
	}
	
	void refresh() throws Exception {
		DataModelCollection coll = (DataModelCollection) XPathUtils.eval(getParentListbox(), "/otp");
		coll.refresh();
	}
	public void addUndo(Event event) throws Exception {
		Window w = (Window) getFellow("add-window");
		w.setVisible(false);
		refresh();
	}

	public void addStep2(Event event) throws Exception {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		CustomField3 type = (CustomField3) w.getFellow("type");
		CustomField3 phone = (CustomField3) w.getFellow("phone");
		CustomField3 email = (CustomField3) w.getFellow("email");
		CustomField3 pin = (CustomField3) w.getFellow("pin0");
		if (type.attributeValidateAll() &&
				(!phone.isVisible() || phone.attributeValidateAll()) &&
				(!email.isVisible() || email.attributeValidateAll())) {
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
			currentDevice.setStatus(OtpStatus.VALIDATED);
			OtpService ejb = (OtpService) new InitialContext().lookup(OtpServiceHome.JNDI_NAME);
			String user = (String) XPathUtils.eval(getParentListbox(), "@userName");
			currentDevice = ejb.registerDevice(user, currentDevice);
			refresh();
			wizard.next();
			Image i = (Image) w.getFellow("image");
			if (currentDevice.getImage() == null) {
				w.getFellow("imageblock").setVisible(false);
				w.getFellow("smsblock").setVisible(true);
			} else {
				w.getFellow("imageblock").setVisible(true);
				w.getFellow("smsblock").setVisible(false);
				i.setContent(currentDevice.getImage());
			}
		}
	}
	
	public void addApply(Event event) throws NamingException, InternalErrorException {
		Window w = (Window) getFellow("add-window");
		w.setVisible(false);
	}

	public String getParentPath() {
		return parentPath;
	}

	public void setParentPath(String parentPath) {
		this.parentPath = parentPath;
	}

	@Override
	protected DataModel getModel() {
		return (DataModel) Path.getComponent(getPage(), model);
	}

	public void setModel(String model) {
		this.model = model;
	}
	
	public DataTable getParentListbox() {
		return (DataTable) Path.getComponent(getPage(), parentPath);
	}
	
	public void select(Event event) {
		Window w = (Window) getFellow("properties-window");
		w.doHighlighted();
	}
	
	public void closeDetails(Event event) {
		Window w = (Window) getFellow("properties-window");
		w.setVisible(false);
	}

	public void changeStatus(Event event) throws CommitException {
		getModel().commit();
	}
}
