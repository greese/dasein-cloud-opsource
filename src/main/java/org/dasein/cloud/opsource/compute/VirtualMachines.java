/**
 * Copyright (C) 2009-2012 enStratus Networks Inc
 *
 * ====================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ====================================================================
 */

package org.dasein.cloud.opsource.compute;


import java.io.StringWriter;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;


import javax.annotation.Nonnull;

import org.apache.log4j.Logger;
import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;
import org.dasein.cloud.OperationNotSupportedException;
import org.dasein.cloud.Tag;
import org.dasein.cloud.compute.Architecture;
import org.dasein.cloud.compute.MachineImage;
import org.dasein.cloud.compute.Platform;
import org.dasein.cloud.compute.VirtualMachine;
import org.dasein.cloud.compute.VirtualMachineProduct;
import org.dasein.cloud.compute.VirtualMachineSupport;
import org.dasein.cloud.compute.VmState;
import org.dasein.cloud.compute.VmStatistics;

import org.dasein.cloud.dc.Region;
import org.dasein.cloud.identity.ServiceAction;
import org.dasein.cloud.opsource.OpSource;
import org.dasein.cloud.opsource.OpSourceMethod;
import org.dasein.cloud.opsource.Param;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class VirtualMachines implements VirtualMachineSupport {
	static public final Logger logger = Logger.getLogger(VirtualMachines.class);
	static private final String DESTROY_VIRTUAL_MACHINE = "delete";
	static private final String CLEAN_VIRTUAL_MACHINE = "clean";
	static private final String REBOOT_VIRTUAL_MACHINE  = "reboot";
	static private final String START_VIRTUAL_MACHINE   = "start";
	static private final String PAUSE_VIRTUAL_MACHINE 	= "shutdown";
	/** Node tag name */
	static private final String Deployed_Server_Tag = "Server";
	static private final String Pending_Deployed_Server_Tag = "PendingDeployServer";

	int attemptForOperation = 30;
	long waitTimeToAttempt = 30000L;

	private OpSource provider;

	public VirtualMachines(OpSource provider) {
		this.provider = provider;
	}    

	public boolean attachDisk(String serverId, int sizeInGb) throws InternalException, CloudException {
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);

		param = new Param(serverId, null);
		parameters.put(1, param);   

		param = new Param("amount", String.valueOf(sizeInGb));
		parameters.put(2, param);      	

		OpSourceMethod method = new OpSourceMethod(provider, 
				provider.buildUrl("addLocalStorage",true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET", null));

		Document doc = method.invoke();

		return method.parseRequestResult("Attaching disk", doc , "result","resultDetail");
	}


	@Override
	public void boot(String serverId) throws InternalException, CloudException {
		/**Start VM*/
		start(serverId);
	}

	private boolean start(String serverId) throws InternalException, CloudException {
		if( logger.isTraceEnabled() ) {
			logger.trace("ENTER: " + VirtualMachine.class.getName() + ".Start()");
		}
		try{
			HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();

			Param param = new Param(OpSource.SERVER_BASE_PATH, null);
			parameters.put(0, param);
			param = new Param(serverId, null);
			parameters.put(1, param);

			OpSourceMethod method = new OpSourceMethod(provider,
					provider.buildUrl(START_VIRTUAL_MACHINE,true, parameters),
					provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
			return method.parseRequestResult("Booting vm",method.invoke(), "result", "resultDetail");
		}finally{
			if( logger.isTraceEnabled() ) {
				logger.trace("EXIT: " + VirtualMachine.class.getName() + ".Start()");
			}
		}
	}

	private boolean cleanFailedVM(String serverId) throws InternalException, CloudException {
		if( logger.isTraceEnabled() ) {
			logger.trace("ENTER: " + VirtualMachine.class.getName() + ".cleanFailedVM()");
		}
		try{
			HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
			Param param = new Param(OpSource.SERVER_BASE_PATH, null);
			parameters.put(0, param);
			param = new Param(serverId, null);
			parameters.put(1, param);

			OpSourceMethod method = new OpSourceMethod(provider,
					provider.buildUrl(CLEAN_VIRTUAL_MACHINE,true, parameters),
					provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
			return method.parseRequestResult("Clean failed vm",method.invoke(),"result", "resultDetail");
		}finally{
			if( logger.isTraceEnabled() ) {
				logger.trace("EXIT: " + VirtualMachine.class.getName() + ".cleanFailedVM()");
			}
		}
	}


	@Override
	public VirtualMachine clone(String serverId, String intoDcId, String name, String description, boolean powerOn, String ... firewallIds) throws InternalException, CloudException {
		throw new OperationNotSupportedException("Instances cannot be cloned.");
	}

	@Override
	public void disableAnalytics(String vmId) throws InternalException, CloudException {
		throw new OperationNotSupportedException("NO OP");
	}

	@Override
	public void enableAnalytics(String vmId) throws InternalException, CloudException {
		throw new OperationNotSupportedException("NO OP");
	}

	@Override
	public String getConsoleOutput(String serverId) throws InternalException, CloudException {
		return "";
	}

	@Override
	public VirtualMachineProduct getProduct(String productId) throws InternalException, CloudException {
		for( Architecture architecture : Architecture.values() ) {
			for( VirtualMachineProduct product : listProducts(architecture) ) {
				if( product.getProductId().equals(productId) ) {
					return product;
				}
			}
		}
		if( logger.isDebugEnabled() ) {
			logger.debug("Unknown product ID for cloud.com: " + productId);
		}
		return null;
	}

	@Override
	public String getProviderTermForServer(Locale locale) {
		return "Server";
	}

	@Override
	public VirtualMachine getVirtualMachine(String serverId) throws InternalException, CloudException {
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);

		param = new Param(serverId, null);
		parameters.put(1, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));

		Document doc = method.invoke();

		NodeList  matches = doc.getElementsByTagName("Server");
		if(matches != null){
			return toVirtualMachine(matches.item(0), false, "");
		}
		if( logger.isDebugEnabled() ) {
			logger.debug("Can not identify VM with ID " + serverId);
		}
		return null;
	}

	public VirtualMachine getVirtualMachineByName(String name) throws InternalException, CloudException {
		if( logger.isDebugEnabled() ) {
			logger.debug("Identify VM with VM Name " + name);
		}

		ArrayList<VirtualMachine> list = (ArrayList<VirtualMachine>) listePendingServers();
		for(VirtualMachine vm : list ){
			if(vm.getName().equals(name)){
				return vm;
			}
		}
		list = (ArrayList<VirtualMachine>) listDeployedServers();
		for(VirtualMachine vm : list ){
			if(vm.getName().equals(name)){
				return vm;
			}
		}
		if( logger.isDebugEnabled() ) {
			logger.debug("Can not identify VM with VM Name " + name);
		}
		return null;
	}

	@Override
	public VmStatistics getVMStatistics(String serverId, long startTimestamp, long endTimestamp) throws InternalException, CloudException {
		return new VmStatistics();
	}

	@Override
	public Iterable<VmStatistics> getVMStatisticsForPeriod(String arg0, long arg1, long arg2) throws InternalException, CloudException {
		return Collections.emptyList();
	}

	@Override
	public boolean isSubscribed() throws CloudException, InternalException {
		return true;
	}

	@Override
	public VirtualMachine launch(String imageId, VirtualMachineProduct product, String inZoneId, String name, String description, String usingKey, String withVlanId, boolean withMonitoring, boolean asSandbox, String... protectedByFirewalls) throws InternalException, CloudException {
		return launch(imageId, product, inZoneId, name, description, usingKey, withVlanId, withMonitoring, asSandbox, protectedByFirewalls, new Tag[0]);
	}

	public VirtualMachine launch(String imageId, VirtualMachineProduct product, String inZoneId, String name, String description, String usingKey, String withVlanId, boolean withMonitoring, boolean asSandbox, String[] protectedByFirewalls, Tag ... tags) throws InternalException, CloudException {
        try{
			/** First step get the target image */
			if( logger.isTraceEnabled() ) {
				logger.trace("ENTER: " + VirtualMachine.class.getName() + ".launch()");
				logger.trace("First step get the target image");
			}
			ServerImage imageSupport = new ServerImage(provider);
			MachineImage origImage = imageSupport.getOpSourceImage(imageId);
			if(origImage == null){
				logger.error("No such image to launch VM");
				throw new CloudException("No such image to launch VM");
			}

			int targetCPU = product.getCpuCount();
			int targetMemory = product.getRamInMb();
			int targetDisk = product.getDiskSizeInGb();

			int currentCPU = 0;
			int currentMemory =0;
			int currentDisk = 10;

			if(origImage.getTag("cpuCount") != null){
				currentCPU = Integer.valueOf((String) origImage.getTag("cpuCount"));
			}

			if(origImage.getTag("memory") != null){
				currentMemory = Integer.valueOf((String) origImage.getTag("memory"));
			}

			if( targetDisk == 0 && currentCPU == targetCPU && currentMemory == targetMemory ){
				boolean isDeployed = this.deploy(origImage.getProviderMachineImageId(), inZoneId, name, description, withVlanId, null, "true");
				if(isDeployed){
					return getVirtualMachineByName(name);
				}else{
					throw new CloudException("Fail to launch the server");
				}

			}else if(targetDisk == 0 && ((targetCPU == 1 && targetMemory == 2048) || (targetCPU == 2 && targetMemory == 4096) || (targetCPU == 4 && targetMemory == 6144))){
				/**  If it is Opsource OS, then get the target image with the same cpu and memory */
				MachineImage targetTmage = imageSupport.searchImage(origImage.getPlatform(), origImage.getArchitecture(), product.getCpuCount(), product.getRamInMb());
				if(targetTmage != null){
					boolean isDeployed = this.deploy(targetTmage.getProviderMachineImageId(), inZoneId, name, description, withVlanId, null, "true");

					if(isDeployed){
						return getVirtualMachineByName(name);
					}else{
						throw new CloudException("Fail to launch the server");
					}
				}
			}
			/** There is target image with the CPU and memory required, then need to modify the server after deploying */

			/** Second step deploy VM */

			if( logger.isTraceEnabled() ) {
				logger.trace("Second step deploy VM");
			}

			boolean isDeployed = this.deploy(imageId, inZoneId, name, description, withVlanId, null, "false");

			long starttime = System.currentTimeMillis();

			/** Third Step Modify VM */
			if(!isDeployed){
				throw new CloudException("Fail to deploy VM");
			}

			VirtualMachine server = getVirtualMachineByName(name);

			/** update the hardware (CPU, memory configuration)*/
			if(server == null){
				throw new CloudException("Server failed to deployed without explaination");
			}

			if(currentCPU != targetCPU || currentMemory != targetMemory ){

				int localAttemptToUpdateVM = attemptForOperation;

				/** Modify server to target cpu and memory */
				while (localAttemptToUpdateVM >0){
					try {
						/** VM has finished deployment before continuing, therefore wait 15s */
						server = getVirtualMachineByName(name);
						if(server == null){
							throw new CloudException("Server failed to launch during modifying the CPU and Memory !!!");
						}

						currentCPU = Integer.valueOf((String) server.getTag("cpuCount"));
						currentMemory = Integer.valueOf((String) server.getTag("memory"));

						if(currentCPU != targetCPU || currentMemory != targetMemory ){
							logger.info("Begin to modify ->" + localAttemptToUpdateVM );
							boolean isModify = modify(server.getProviderVirtualMachineId(), targetCPU, targetMemory);

							if(isModify){
								localAttemptToUpdateVM = 0;
							}
						}else{
							localAttemptToUpdateVM = 0;
						}

					} catch (InternalException e) {
						/** Throwable? */
					} catch (CloudException e) {
						try{
							Thread.sleep(waitTimeToAttempt); //Wait 30000L
							localAttemptToUpdateVM--;
						}catch(InterruptedException e1){
							logger.info("InterruptedException while trying to wait 30s to update the server with Id ");
						}
					}
				}
				if(logger.isTraceEnabled()){
					long end = System.currentTimeMillis();
					logger.trace("Total deploy time -> " + ((end-starttime)/1000));
				}
			}

			/** Third Step: attach the disk */

			if( targetDisk != currentDisk){

				/** Update usually take another 6 mins */
				starttime = System.currentTimeMillis();
				int localAttemptToAttachDisk = attemptForOperation;

				while (localAttemptToAttachDisk >0){
					try {
						//Begin to attach the VM
						if(logger.isTraceEnabled()){
							logger.trace("Begin to attach the server " + localAttemptToAttachDisk);
						}
						server = getVirtualMachineByName(name);
						if(server == null){
							throw new CloudException("Server failed to launch while attaching disk !!!");
						}
						if(server.getProduct() != null && (server.getProduct().getDiskSizeInGb() == targetDisk) ){
							localAttemptToAttachDisk = 0;
						}

						boolean isAttached = attachDisk(server.getProviderVirtualMachineId(), targetDisk);

						if(isAttached){
							localAttemptToAttachDisk = 0;
						}

						if(logger.isTraceEnabled()){
							long end = System.currentTimeMillis();
							logger.info("Total attach time -> " + ((end-starttime)/1000));
						}

					} catch (InternalException e) {
						/** throwable */
					} catch (CloudException e) {
						try{
							Thread.sleep(waitTimeToAttempt);
							localAttemptToAttachDisk--;

						}catch (InterruptedException e1) {
							logger.info("InterruptedException while trying to wait 30s to attaching disk to the server ");
						}
					}
				}
			}

			/**  Fourth Step: boot the server */
			/** Update usually take another 10 mins, wait 5 minutes first */
			starttime = System.currentTimeMillis();
			int localAttemptToBootVM = attemptForOperation;

			while (localAttemptToBootVM >0){
				try {
					/** Begin to start the VM */
					server = getVirtualMachineByName(name);
					if(server == null){
						throw new CloudException("Server failed to launch while booting !!!");
					}

					if(server.getCurrentState().equals(VmState.RUNNING)){
						/** Already started	*/
						return server;
					}
					/** Start VM*/
					start(server.getProviderVirtualMachineId());

					if(logger.isTraceEnabled()){
						long end = System.currentTimeMillis();
						logger.info("Total boot time -> " + ((end-starttime)/1000));
					}
					return server;
				} catch (InternalException e) {

				} catch (CloudException e) {
					try{

						Thread.sleep(waitTimeToAttempt);

						localAttemptToBootVM--;

					}catch (InterruptedException e1) {
						logger.warn("InterruptedException while trying to wait 30s to update the server with Id ");
					}
				}
			}
			return null;
		}finally{
			if( logger.isTraceEnabled() ) {
				logger.trace("EXIT: " + VirtualMachine.class.getName() + ".launch()");
			}
		}
	}

	/**
	 *
	 * @param imageId
	 * @param inZoneId
	 * @param name
	 * @param description
	 * @param withVlanId
	 * @param adminPassword
	 * @param isStart: true or false
	 */

	private boolean deploy(@Nonnull String imageId, String inZoneId, String name, String description, String withVlanId, String adminPassword, String isStart) throws InternalException, CloudException {
		inZoneId = translateZone(inZoneId);
		/** Create post body */
		Document doc = provider.createDoc();
		Element server = doc.createElementNS("http://oec.api.opsource.net/schemas/server", "Server");

		Element nameElmt = doc.createElement("name");
		nameElmt.setTextContent(name);

		Element descriptionElmt = doc.createElement("description");
		descriptionElmt.setTextContent(description);

		if(withVlanId == null){
			withVlanId = provider.getDefaultVlanId();
		}

		Element vlanResourcePath = doc.createElement("vlanResourcePath");
		vlanResourcePath.setTextContent(provider.getVlanResourcePathFromVlanId(withVlanId));

		Element imageResourcePath = doc.createElement("imageResourcePath");
		imageResourcePath.setTextContent(provider.getImageResourcePathFromImaged(imageId));

		if(adminPassword == null){
			adminPassword = provider.getDefaultAdminPasswordForVM();
		}else{
			if(adminPassword.length() < 8){
				throw new InternalException("Password require a minimum of 8 characters!!!");
			}
		}

		Element administratorPassword = doc.createElement("administratorPassword");
		administratorPassword.setTextContent(adminPassword);

		Element isStartElmt = doc.createElement("isStarted");

		isStartElmt.setTextContent(isStart);

		server.appendChild(nameElmt);
        server.appendChild(descriptionElmt);
        server.appendChild(vlanResourcePath);
        server.appendChild(imageResourcePath);
        server.appendChild(administratorPassword);

        server.appendChild(isStartElmt);
        doc.appendChild(server);

        HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();

		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "POST", provider.convertDomToString(doc)));
		return method.parseRequestResult("Deploying server",method.invoke(), "result", "resultDetail");
	}


	@Override
	public Iterable<String> listFirewalls(String vmId) throws InternalException, CloudException {
		/** Firewall Id is the same as the network ID*/
		VirtualMachine vm = this.getVirtualMachine(vmId);

		if(vm == null){
			return Collections.emptyList();
		}
		String networkId = vm.getProviderVlanId();
		if(networkId != null){
			ArrayList<String> list = new ArrayList<String>();
			list.add(networkId);
			return list;
		}
		return Collections.emptyList();
	}

	@Override
	public Iterable<VirtualMachineProduct> listProducts(Architecture architecture) throws InternalException, CloudException {
		List<VirtualMachineProduct> products = new ArrayList<VirtualMachineProduct>();

		VirtualMachineProduct product;
		/** OpSource enables any combination of CPU (1 -8 for East 1-4 or west) and RAM (1 - 64G for East and 1-32G for west) */

		int maxCPUNum = 0, maxMemInGB =0,  diskSizeInGb = 0;

		/** Obtain the maximum CPU and Memory for each data center */
		String regionId = provider.getDefaultRegionId();
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.LOCATION_BASE_PATH, null);
		parameters.put(0, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));

		Document doc = method.invoke();
        String sNS = "";
        try{
            sNS = doc.getDocumentElement().getTagName().substring(0, doc.getDocumentElement().getTagName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}
		NodeList blocks = doc.getElementsByTagName(sNS + "datacenterWithLimits");

		if(blocks != null){
			for(int i=0; i< blocks.getLength();i++){
				Node item = blocks.item(i);

				RegionComputingPower r = toRegionComputingPower(item, sNS);
				if( r.getProviderRegionId().equals(regionId)){
					maxCPUNum = r.getMaxCPUNum();
					maxMemInGB = r.getMaxMemInMB()/1024;
				}
			}
		}

		for( int disk = 0 ; disk < 6; disk ++ ){
			diskSizeInGb = disk * 50;

			for(int cpuNum =1;cpuNum <= maxCPUNum;cpuNum ++){
				/**
				 * Default cpuNum = 1, 2, max ram = 8
				 * cpuNum = 3, 4, min ram 4, max ram = 32
				 * cpuNum = 1, 2, max ram = 8
				 */
				int ramInGB = 1*cpuNum;
				if(cpuNum <=2){
					ramInGB = 1;
				}
				while(ramInGB <= 4*cpuNum && ramInGB <=  maxMemInGB){
					product = new VirtualMachineProduct();
					product.setProductId(cpuNum+ ":" +ramInGB + ":" + disk);
					product.setName(" (" + cpuNum + " CPU/" + ramInGB + " Gb RAM/" + diskSizeInGb + " Gb Disk)");
					product.setDescription(" (" + cpuNum + " CPU/" + ramInGB + " Gb RAM/" + diskSizeInGb + " Gb Disk)");
					product.setRamInMb(ramInGB*1024);
					product.setCpuCount(cpuNum);
					product.setDiskSizeInGb(diskSizeInGb);
					products.add(product);

					if(cpuNum <=2){
						ramInGB = ramInGB + 1;
					}else{
						ramInGB = ramInGB + ramInGB;
					}
				}
			}
		}
		return products;
	}

	@Override
	public Iterable<VirtualMachine> listVirtualMachines() throws InternalException, CloudException {
		ArrayList<VirtualMachine> allList = new ArrayList<VirtualMachine>();
		/** List the pending Server first */
		ArrayList<VirtualMachine> list = (ArrayList<VirtualMachine>) listePendingServers();

		if(list != null){
			allList.addAll(list);
		}
		/** List the deployed Server */
		list = (ArrayList<VirtualMachine>) listDeployedServers();
		if(list != null){
			allList.addAll(list);
		}
		return allList;
	}

	private Iterable<VirtualMachine> listDeployedServers() throws InternalException, CloudException {
		ArrayList<VirtualMachine> list = new ArrayList<VirtualMachine>();

		/** Get deployed Server */
		HashMap<Integer, Param> parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param("deployed", null);
		parameters.put(1, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null, true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));

		Document doc = method.invoke();

		NodeList matches = doc.getElementsByTagName("DeployedServer");

		if(matches != null){
			for( int i=0; i<matches.getLength(); i++ ) {
				Node node = matches.item(i);
				VirtualMachine vm = this.toVirtualMachine(node, false, "");
				if( vm != null ) {
					list.add(vm);
				}
			}
		}
		return list;
	}


	private Iterable<VirtualMachine> listePendingServers() throws InternalException, CloudException {
		ArrayList<VirtualMachine> list = new ArrayList<VirtualMachine>();

		/** Get pending deploy server */
		HashMap<Integer, Param> parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param("pendingDeploy", null);
		parameters.put(1, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null, true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));

		Document doc = method.invoke();

		NodeList matches = doc.getElementsByTagName(Pending_Deployed_Server_Tag);
		if(matches != null){
			for( int i=0; i<matches.getLength(); i++ ) {
				Node node = matches.item(i);
				VirtualMachine vm = this.toVirtualMachine(node, true, "");
				if( vm != null ) {
					list.add(vm);
				}
			}
		}
		return list;
	}


	@Override
	public @Nonnull String[] mapServiceAction(@Nonnull ServiceAction action) {
		return new String[0];
	}

	/** Modify VM with the cpu and memory */
	private boolean modify(String serverId, int cpuCount, int memoryInMb ) throws InternalException, CloudException {

		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param(serverId, null);
		parameters.put(1, param);

		/** Create post body */
		String requestBody = "cpuCount=";
		requestBody += cpuCount;
		requestBody += "&memory=" + memoryInMb;

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(null,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Modify, "POST", requestBody));
		return method.parseRequestResult("Modify vm",method.invoke(), "result", "resultDetail");
	}

	@Override
	public void pause(String serverId) throws InternalException, CloudException {
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param(serverId, null);
		parameters.put(1, param);

		/** Gracefully power off */
		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(PAUSE_VIRTUAL_MACHINE,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
		method.parseRequestResult("Pauseing vm",method.invoke(),"result","resultDetail");
	}


	@Override
	public void reboot(String serverId) throws CloudException, InternalException {
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param(serverId, null);
		parameters.put(1, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(REBOOT_VIRTUAL_MACHINE,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
		method.parseRequestResult("Rebooting vm",method.invoke(),"result","resultDetail");
	}

	@Override
	public boolean supportsAnalytics() throws CloudException, InternalException {
		return false;
	}

	@Override
	public void terminate(String serverId) throws InternalException, CloudException {
		VirtualMachine server = getVirtualMachine(serverId);

		if(server == null){
			throw new CloudException("No such VM");
		}

		/** Release public IP first */
		if(server.getPublicIpAddresses() != null){
			for(String addressId : server.getPublicIpAddresses()){
				provider.getNetworkServices().getIpAddressSupport().releaseFromServer(addressId);
			}
		}

		/** Now Pause the vm */

		int localAttemptToPauseVM = attemptForOperation;

		while (localAttemptToPauseVM >0){
			try {
				/** If it is pending, means it is in deployment process, need around 6 mins */
				server = getVirtualMachine(serverId);

				if(server == null){
					/** VM already killed */
					return;
				}

				if(server.getCurrentState().equals(VmState.RUNNING)){
					pause(serverId);
				}else{
					localAttemptToPauseVM = 0;
				}

			} catch (InternalException e) {

			} catch (CloudException e){
				try {
					Thread.sleep(waitTimeToAttempt);
					localAttemptToPauseVM--;
				} catch (InterruptedException e1) {
					throw new InternalException ("Fail when waiting");
				}
			}

			int localAttemptToTerminateVM = attemptForOperation;

			while (localAttemptToTerminateVM >0){
				try {
					/** Begin to Kill the VM */
					server = getVirtualMachine(serverId);
					if(server == null){
						/** VM already killed */
						return;
					}

					/**  In case the server is up from the booting stage */
					if(server.getCurrentState().equals(VmState.RUNNING)){
						pause(serverId);
						localAttemptToTerminateVM = attemptForOperation;
					}
					else{
						logger.info("Begin to kill -> " + localAttemptToTerminateVM);
						String  resultCode = killVM(serverId);
						if(resultCode.equals("REASON_0")){
							/** Kill VM successfully */
							localAttemptToTerminateVM = 0;
						}
						else if(resultCode.equals("REASON_395")){
							logger.error("Could not find the server with Id" + serverId );
							localAttemptToTerminateVM = 0;
						}
						else if(resultCode.equals("REASON_100")){
							logger.error(" Invalid Credentials ");
							localAttemptToTerminateVM = 0;
						}
						else if(resultCode.equals("REASON_393")){
							logger.error("The server with " + serverId + " is associated with a Real-Server in load balancer");
							localAttemptToTerminateVM = 0;
						}
						else{
							try{
								Thread.sleep(waitTimeToAttempt);
								localAttemptToTerminateVM--;
								//Failed deploy
								logger.info("Clean Failed Deploy");
								cleanFailedVM(serverId);
							} catch (Throwable notPartOfTest ) {
								//ignore
							}
						}
					}
				} catch (InternalException e) {
					logger.error(e.getMessage());
				} catch (CloudException e) {
					logger.error(e.getMessage());
					try{
						Thread.sleep(waitTimeToAttempt);
						localAttemptToTerminateVM--;
						//Failed deploy
						logger.info("Clean Failed Deploy");
						cleanFailedVM(serverId);
					} catch (Throwable notPartOfTest ) {
						//ignore
					}
				}
			}
		}
	}

	private String killVM(String serverId) throws InternalException, CloudException {
		HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
		Param param = new Param(OpSource.SERVER_BASE_PATH, null);
		parameters.put(0, param);
		param = new Param(serverId, null);
		parameters.put(1, param);

		OpSourceMethod method = new OpSourceMethod(provider,
				provider.buildUrl(DESTROY_VIRTUAL_MACHINE,true, parameters),
				provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
		return method.requestResultCode("Terminating vm",method.invoke(),"resultCode");
	}

	private String translateZone(String zoneId) throws InternalException, CloudException {
		if( zoneId == null ) {
			for( Region r : provider.getDataCenterServices().listRegions() ) {
				zoneId = r.getProviderRegionId();
				break;
			}
		}
		/*if(zoneId.endsWith("a")){
			zoneId = zoneId.substring(0, zoneId.length()-1);       	
		}*/
		return zoneId;
	}

	private VirtualMachineProduct getProduct(Architecture architecture, int cpuCout, int memoryInSize, int diskInGB) throws InternalException, CloudException{

		for( VirtualMachineProduct product : listProducts(architecture) ) {
			if( product.getCpuCount() == cpuCout && product.getRamInMb() == memoryInSize  && diskInGB == product.getDiskSizeInGb() ) {
				return product;
			}
		}      
		return null;
	}

	private VirtualMachine toVirtualMachine(Node node, Boolean isPending, String nameSpace) throws CloudException, InternalException {
		if( node == null ) {
			return null;
		}
		HashMap<String,String> properties = new HashMap<String,String>();
		VirtualMachine server = new VirtualMachine();
		NodeList attributes = node.getChildNodes();

		Architecture bestArchitectureGuess = Architecture.I64;

		server.setTags(properties);

		if(isPending){
			server.setCurrentState(VmState.PENDING);
			server.setImagable(false);
		}else{
			server.setCurrentState(VmState.RUNNING);
			server.setImagable(true);
		}        
		server.setProviderOwnerId(provider.getContext().getAccountNumber());
		server.setClonable(false);        
		server.setPausable(true);
		server.setPersistent(true);

		server.setProviderRegionId(provider.getContext().getRegionId());

		for( int i=0; i<attributes.getLength(); i++ ) {
			Node attribute = attributes.item(i);
			if(attribute.getNodeType() == Node.TEXT_NODE) continue;
			String name = attribute.getNodeName();
			String value;

			if( attribute.getChildNodes().getLength() > 0 ) {
				value = attribute.getFirstChild().getNodeValue();                
			}
			else {
				continue;
			}
			/** Specific server node information */
        
        
            String nameSpaceString = "";
            if(!nameSpace.equals("")) nameSpaceString = nameSpace + ":";
			if( name.equals(nameSpaceString + "id") || name.equals("id") ) {
				server.setProviderVirtualMachineId(value);                
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "name") ) {
				server.setName(value);
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "description") ) {
				server.setDescription(value);
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "vlanResourcePath") ) {                
				String vlanId = provider.getVlanIdFromVlanResourcePath(value);
				if(!provider.isVlanInRegion(vlanId)){
					return null;
				}
				server.setProviderVlanId(vlanId); 
			} 
			else if( name.equalsIgnoreCase(nameSpaceString + "operatingSystem") ) {            	
				NodeList osAttributes  = attribute.getChildNodes();
				for(int j=0;j<osAttributes.getLength();j++ ){
					Node os = osAttributes.item(j);
					String osName = os.getNodeName();              
					String osValue ;
					if( osName.equals(nameSpaceString + "displayName") && os.getChildNodes().getLength() > 0 ) {
						osValue = os.getFirstChild().getNodeValue();
					}else{
						osValue = null ; 
					}

					if( osValue != null && osValue.contains("64") ) {
						bestArchitectureGuess = Architecture.I64;
					}
					else if( osValue != null && osValue.contains("32") ) {
						bestArchitectureGuess = Architecture.I32;
					}
					if( osValue != null ) {
						server.setPlatform(Platform.guess(osValue));
						break;
					}           		 
				}           
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "cpuCount") ) {
				server.getTags().put("cpuCount", value);
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "memory") ) { 
				server.getTags().put("memory", value);
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "osStorage") ) { 
				server.getTags().put("osStorage", value);
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "additionalLocalStorage") ) { 
				server.getTags().put("additionalLocalStorage", value);
			}
			else if(name.equals(nameSpaceString + "machineName") ) { 
				//equal to private ip address
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "privateIPAddress") ) { 
				if( value != null ) {
					server.setPrivateIpAddresses(new String[] { value });  
					server.setProviderAssignedIpAddressId(value);
				}          
			}
			//DeployedServer
			else if( name.equalsIgnoreCase(nameSpaceString + "publicIpAddress") ) { 
				server.setPublicIpAddresses(new String[] { value });               
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "isDeployed") ) {
				if(value.equalsIgnoreCase("false")){
					server.setCurrentState(VmState.PENDING); 
					isPending = true;
				}else{
					isPending = false;
				}         
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "isStarted") ) {        	   
				if(!isPending && value.equalsIgnoreCase("false")){
					server.setCurrentState(VmState.PAUSED);
				}           
			}
			else if( name.equalsIgnoreCase(nameSpaceString + "created") ) {
				DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); 
				/** 2012-05-08T02:23:16.999Z */
				try {
					if(value.contains(".")){
						String newvalue = value.substring(0,value.indexOf("."))+"Z";
						server.setCreationTimestamp(df.parse(newvalue).getTime());                		
					}else{
						server.setCreationTimestamp(df.parse(value).getTime());                		
					}                    
				}
				catch( ParseException e ) {
					logger.warn("Invalid date: " + value);
					server.setLastBootTimestamp(0L);
				}
			}
			//From here is the deployed server, or pending server
			else if(name.equalsIgnoreCase(nameSpaceString + "machineSpecification") ) {
				NodeList machineAttributes  = attribute.getChildNodes();
				for(int j=0;j<machineAttributes.getLength();j++ ){
					Node machine = machineAttributes.item(j);	           		
					if(machine.getNodeType() == Node.TEXT_NODE) continue;	           		

					if(machine.getNodeName().equalsIgnoreCase(nameSpaceString + "operatingSystem") ){
						NodeList osAttributes  = machine.getChildNodes();
						for(int k=0;k<osAttributes.getLength();k++ ){
							Node os = osAttributes.item(k);

							if(os.getNodeType() == Node.TEXT_NODE) continue;
							String osName = os.getNodeName();              
							String osValue = null ;

							if(osName.equalsIgnoreCase(nameSpaceString + "displayName") && os.getChildNodes().getLength() > 0 ) {
								osValue = os.getFirstChild().getNodeValue();
							}else if(osName.equalsIgnoreCase(nameSpaceString + "type") && os.getChildNodes().getLength() > 0) {
								osValue = os.getFirstChild().getNodeValue();
								server.setPlatform(Platform.guess(osValue));			                       
							}
							if(osValue != null && osValue.contains("64") ) {
								bestArchitectureGuess = Architecture.I64;
							}
							else if(osValue != null && osValue.contains("32") ) {
								bestArchitectureGuess = Architecture.I32;
							}		            		     		 
						}
					}else if( machine.getNodeName().equalsIgnoreCase(nameSpaceString + "cpuCount") && machine.getFirstChild().getNodeValue() != null ) {
						server.getTags().put("cpuCount", machine.getFirstChild().getNodeValue());
					}
					/** memoryMb pendingDeploy deployed */
					else if( (machine.getNodeName().equalsIgnoreCase("memory") || machine.getNodeName().equalsIgnoreCase(nameSpaceString + "memoryMb"))&& machine.getFirstChild().getNodeValue() != null ) {
						server.getTags().put("memory", machine.getFirstChild().getNodeValue());
					}
					/** deployedserver osStorageGb */
					else if( (machine.getNodeName().equalsIgnoreCase(nameSpaceString + "osStorage") ||machine.getNodeName().equalsIgnoreCase(nameSpaceString + "osStorageGb"))&& machine.getFirstChild().getNodeValue() != null) {
						server.getTags().put("osStorage", machine.getFirstChild().getNodeValue());
					}
					/** additionalLocalStorageGb pendingDeploy */
					else if((machine.getNodeName().equalsIgnoreCase(nameSpaceString + "additionalLocalStorage") || machine.getNodeName().equalsIgnoreCase(nameSpaceString + "additionalLocalStorageGb") ) && machine.getFirstChild().getNodeValue() != null ) {
						server.getTags().put("additionalLocalStorage", machine.getFirstChild().getNodeValue());
					}                     
				}           
			}
			/** pendingDeploy or Deployed */
			else if( name.equalsIgnoreCase(nameSpaceString + "sourceImageId") ) {
				server.setProviderMachineImageId(value);
			}
			/** pendingDeploy or Deployed */
			else if( name.equalsIgnoreCase(nameSpaceString + "networkId") ) {
				server.setProviderVlanId(value);        	   
				if(!provider.isVlanInRegion(value)){
					return null;
				}         
			}
			/** From here is the specification for pending deployed server */
			else if( name.equalsIgnoreCase(nameSpaceString + "status") ) {
				NodeList statusAttributes  = attribute.getChildNodes();
				for(int j=0;j<statusAttributes.getLength();j++ ){
					Node status = statusAttributes.item(j);
					if(status.getNodeType() == Node.TEXT_NODE) continue;
					if( status.getNodeName().equalsIgnoreCase(nameSpaceString + "step") ){
						//TODO
						/** If it is this status means it is pending */
						server.setCurrentState(VmState.PENDING);
					}
					else if( status.getNodeName().equalsIgnoreCase(nameSpaceString + "requestTime") && status.getFirstChild().getNodeValue() != null ) {
						DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ"); //2009-02-03T05:26:32.612278

						try {
							if(value.contains(".")){
								String newvalue = value.substring(0,status.getFirstChild().getNodeValue().indexOf("."))+"Z";
								server.setCreationTimestamp(df.parse(newvalue).getTime());                		
							}else{
								server.setCreationTimestamp(df.parse(status.getFirstChild().getNodeValue()).getTime());                		
							}                    
						}
						catch( ParseException e ) {
							logger.warn("Invalid date: " + value);
							server.setLastBootTimestamp(0L);
						}
					}  
					else if( status.getNodeName().equalsIgnoreCase(nameSpaceString + "userName") && status.getFirstChild().getNodeValue() != null ) {
						//This seems to break the cloud syncing operation - removed for now.
						//server.setProviderOwnerId(status.getFirstChild().getNodeValue());
					}
					else if( status.getNodeName().equalsIgnoreCase(nameSpaceString + "numberOfSteps") ) {

					}
					else if( status.getNodeName().equalsIgnoreCase(nameSpaceString + "action") ) {
						String action = status.getFirstChild().getNodeValue();
						if(action.equalsIgnoreCase("CLEAN_SERVER")){
							/** Means failed deployed */
							server.setCurrentState(VmState.PENDING);	   
						}
					}
				}           
			}
		}      

		if( server.getName() == null ) {
			server.setName(server.getProviderVirtualMachineId());
		}
		if( server.getDescription() == null ) {
			server.setDescription(server.getName());
		}
	
		if( server.getProviderDataCenterId() == null ) {        	
			server.setProviderDataCenterId(provider.getDataCenterId(server.getProviderRegionId()));
		}       

		if( server.getPlatform() == null && server.getName() != null ) {
			server.setPlatform(Platform.guess(server.getName()));        	
		}
		else {
			server.setPlatform(Platform.UNKNOWN);
		}
		if( server.getArchitecture() == null ) {
			server.setArchitecture(bestArchitectureGuess);
		}

		VirtualMachineProduct product = new VirtualMachineProduct();
		if(server.getTag("cpuCount") != null && server.getTag("memory") != null ){
			int cpuCout = Integer.valueOf((String) server.getTag("cpuCount"));
			int memoryInMb = Integer.valueOf((String) server.getTag("memory"));

			if(server.getTag("additionalLocalStorage") == null){
				product = getProduct(bestArchitectureGuess, cpuCout, memoryInMb, 0);
			}else{
				int diskInGb = Integer.valueOf((String) server.getTag("additionalLocalStorage"));
				product = getProduct(bestArchitectureGuess, cpuCout, memoryInMb, diskInGb); 
			}
		}

		/**  Set public address */
		/**        String[] privateIps = server.getPrivateIpAddresses();

        if(privateIps != null){
            IpAddressImplement ipAddressSupport = new IpAddressImplement(provider);
            String[] publicIps = new String[privateIps.length];
            for(int i= 0; i< privateIps.length; i++){
            	NatRule rule = ipAddressSupport.getNatRule(privateIps[i], server.getProviderVlanId());
            	if(rule != null){
            		publicIps[i] = rule.getNatIp();
            	}               
            }
            server.setPublicIpAddresses(publicIps);
        }*/

		server.setProduct(product);
		return server;
	}

	private RegionComputingPower toRegionComputingPower(Node node, String nameSpace){

		if(node == null){
			return null;
		}

		NodeList data;

		data = node.getChildNodes();

		RegionComputingPower r = new RegionComputingPower();
		for( int i=0; i<data.getLength(); i++ ) {
			Node item = data.item(i);

            
			if(item.getNodeType() == Node.TEXT_NODE) continue;

			if( item.getNodeName().equals(nameSpace + "location") ) {
				r.setProviderRegionId(item.getFirstChild().getNodeValue());
			}
			else if( item.getNodeName().equals(nameSpace + "displayName") ) {
				r.setName(item.getFirstChild().getNodeValue());
			}
			else if( item.getNodeName().equals(nameSpace + "maxCpu") ) {
				r.setMaxCPUNum(Integer.valueOf(item.getFirstChild().getNodeValue()));
			}
			else if( item.getNodeName().equals(nameSpace + "maxRamMb") ) {
				r.setMaxMemInMB(Integer.valueOf(item.getFirstChild().getNodeValue()));
			}
		}
		return r;
	}


	@SuppressWarnings("serial")
	public class RegionComputingPower extends Region{

		public int maxCPUNum;
		public int maxMemInMB;

		public int getMaxMemInMB(){
			return maxMemInMB;
		}

		public int getMaxCPUNum(){
			return maxCPUNum;
		}

		public void setMaxMemInMB(int maxMemInMB){
			this.maxMemInMB = maxMemInMB;
		}

		public void setMaxCPUNum(int maxCPUNum){
			this.maxCPUNum = maxCPUNum;
		}
	}
}
