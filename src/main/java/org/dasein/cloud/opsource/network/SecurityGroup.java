/**
 * Copyright (C) 2011-2012 enStratus Networks Inc
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

package org.dasein.cloud.opsource.network;

import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;

import org.apache.log4j.Logger;
import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;
import org.dasein.cloud.OperationNotSupportedException;
import org.dasein.cloud.identity.ServiceAction;
import org.dasein.cloud.network.Direction;
import org.dasein.cloud.network.Firewall;
import org.dasein.cloud.network.FirewallRule;
import org.dasein.cloud.network.FirewallSupport;
import org.dasein.cloud.network.Permission;
import org.dasein.cloud.network.Protocol;
import org.dasein.cloud.opsource.CallCache;
import org.dasein.cloud.opsource.OpSource;
import org.dasein.cloud.opsource.OpSourceMethod;
import org.dasein.cloud.opsource.Param;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.annotation.Nonnull;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * There is no concept of firewall group in OpSource,
 * but it supports the idea of firewall rule.
 * Therefore, in this implementation, the firewall group idea would be
 * the same with the network group. 
 * The create and delete firewall group will not be supported.
 * But list and get firewall would be list and get network.
 *
 */
public class SecurityGroup implements FirewallSupport {
    static private final Logger logger = Logger.getLogger(SecurityGroup.class);
    
    static public final String AUTHORIZE_SECURITY_GROUP_INGRESS = "authorizeSecurityGroupIngress";
    static public final String CREATE_SECURITY_GROUP            = "createSecurityGroup";
    static public final String DELETE_SECURITY_GROUP            = "deleteSecurityGroup";
    static public final String LIST_SECURITY_GROUPS             = "listSecurityGroups";
    static public final String REVOKE_SECURITY_GROUP_INGRESS    = "revokeSecurityGroupIngress";
    
    private OpSource provider;
    
    SecurityGroup(OpSource provider) { this.provider = provider; }
    
    /**
     * URL: https://<Cloud API URL>/oec/0.9/{org-id}/network/{networkid}/aclrule
	**/    
    @Override
    @Deprecated
    public @Nonnull String authorize(@Nonnull String firewallId, @Nonnull String cidr, @Nonnull Protocol protocol, int startPort, int endPort) throws CloudException, InternalException {
        return authorize(firewallId, Direction.INGRESS, cidr, protocol, startPort, endPort);
    }

    @Override
    public @Nonnull String authorize(@Nonnull String firewallId, @Nonnull Direction direction, @Nonnull String cidr, @Nonnull Protocol protocol, int beginPort, int endPort) throws CloudException, InternalException {
        if( !Direction.INGRESS.equals(direction) ) {
            throw new OperationNotSupportedException("No egress rules allowed yet");
        }
        HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.NETWORK_BASE_PATH, null);
        parameters.put(0, param);

        param = new Param(firewallId, null);
        parameters.put(1, param);

        param = new Param("aclrule", null);
        parameters.put(2, param);

        /** Create post body */
        Document doc = provider.createDoc();
        Element aclRule = doc.createElementNS("http://oec.api.opsource.net/schemas/network", "AclRule");
        Element nameElmt = doc.createElement("name");
        nameElmt.setTextContent(cidr);

        Element positionElmt = doc.createElement("position");

        String positionId = getFirstAvaiablePositionForInsertRule(firewallId);
        if(positionId == null){
            throw new CloudException("Can not add firewall Rule because no position availabe to insert the current rule !!!");
        }else{
            positionElmt.setTextContent(positionId);
        }

        Element actionElmt = doc.createElement("action");
        //<!-- mandatory, string, one of (PERMIT,DENY) -->
        actionElmt.setTextContent("PERMIT");

        Element protocolElmt = doc.createElement("protocol");
        protocolElmt.setTextContent(protocol.name());

        String ipAddress="0.0.0.0";
        String mask = null;

        if(cidr != null){
            String[] ipInfo = cidr.split("/");
            ipAddress = ipInfo[0];
            if(ipInfo.length >1){
                mask = convertNetMask(ipInfo[1]);
            }
        }

        Element sourceIpRange = doc.createElement("sourceIpRange");
        Element sourceIpAddress = doc.createElement("ipAddress");
        sourceIpAddress.setTextContent(ipAddress);
        sourceIpRange.appendChild(sourceIpAddress);

        /** OpSource can not accept cidr style as IP/255.255.255.255, therefore when it is only one IP, ignore */
        if(mask != null && !mask.equals("255.255.255.255") ){
            Element sourceNetMask = doc.createElement("netmask");
            sourceNetMask.setTextContent(mask);
            sourceIpRange.appendChild(sourceNetMask);
        }
        Element destinationIpRange = doc.createElement("destinationIpRange");
        Element portRange = doc.createElement("portRange");
        Element type = doc.createElement("type");

        /** (ALL,EQUAL_TO,RANGE,GREATER_THAN,LESS_THAN); Set as default EQUAL_TO */
        type.setTextContent("EQUAL_TO");

        Element port = doc.createElement("port1");
        port.setTextContent(String.valueOf(beginPort));
        portRange.appendChild(type);
        portRange.appendChild(port);

        aclRule.appendChild(nameElmt);
        aclRule.appendChild(positionElmt);
        aclRule.appendChild(actionElmt);
        aclRule.appendChild(protocolElmt);
        aclRule.appendChild(protocolElmt);
        aclRule.appendChild(sourceIpRange);
        aclRule.appendChild(destinationIpRange);
        aclRule.appendChild(portRange);
        doc.appendChild(aclRule);

        OpSourceMethod method = new OpSourceMethod(provider,
                provider.buildUrl(null,true, parameters),
                provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "POST", provider.convertDomToString(doc)));
        Document responseDoc = method.invoke();

        Node item = responseDoc.getDocumentElement();
        String sNS = "";
        try{
            sNS = item.getNodeName().substring(0, item.getNodeName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}
        NodeList matches = item.getChildNodes();
        if(matches != null){
            for( int i=0; i<matches.getLength(); i++ ) {
                Node node = matches.item(i);
                if(node.getNodeName().equals(sNS + "id") && node.getFirstChild().getNodeValue() != null ){
                    return node.getFirstChild().getNodeValue();
                }

            }
        }
        throw new CloudException("Fails to authorizing firewall rule without explaination!");
    }

    public String convertNetMask(String mask){
    	if(mask == null){
    		return "255.255.255.255";
    	}
    	if(mask.contains(".")){
    		return mask;
    	}
    	int prefix;
    	try  
    	{  
    		prefix = Integer.parseInt(mask);
    		
    	}catch(NumberFormatException nfe)  
    	{  
    		prefix = 0;  
    	 }
    	
    	int maskValue = 0xffffffff << (32 - prefix);
    	int value = maskValue;
    	byte[] bytes = new byte[]{ 
    	            (byte)(value >>> 24), (byte)(value >> 16 & 0xff), (byte)(value >> 8 & 0xff), (byte)(value & 0xff) };

    	InetAddress netAddr;
		
    	try {
			netAddr = InetAddress.getByAddress(bytes);
	    	return netAddr.getHostAddress();
		} catch (UnknownHostException e) {
			return "255.255.255.255";
		}
    }
   
    // 
    private String convertCidr(String cidr){
    	String mask = "255.255.255.255";
		if(cidr != null){
			String[] ipInfo = cidr.split("/");
			String ipAddress = ipInfo[0];
			if(ipInfo.length >1){
				mask = convertNetMask(ipInfo[1]);
			}
			return ipAddress +"/" + mask;
		}		
    	return null;
    }
    
    public String getNetMask(String mask){
    	if(mask == null){
    		return "255.255.255.255";
    	}
    	if(mask.contains(".")){
    		return mask;
    	}
    	int prefix;
    	try{  
    		prefix = Integer.parseInt(mask);
    	}catch(NumberFormatException nfe){  
    		prefix = 0;  
    	}
    	
    	int maskValue = 0xffffffff << (32 - prefix);
    	int value = maskValue;
    	byte[] bytes = new byte[]{ 
    	            (byte)(value >>> 24), (byte)(value >> 16 & 0xff), (byte)(value >> 8 & 0xff), (byte)(value & 0xff) };

    	InetAddress netAddr;
		try {
			netAddr = InetAddress.getByAddress(bytes);
	    	return netAddr.getHostAddress();
		} catch (UnknownHostException e) {
			return "255.255.255.255";
		}
    }

    @Override
    public String create(String name, String description) throws InternalException, CloudException {
    	/** Does not support create Firewall */
    	throw new CloudException("No Op");
    }

    @Override
    public String createInVLAN(String name, String description, String providerVlanId) throws InternalException, CloudException {
    	/** Does not support create Firewall */
    	throw new CloudException("No Op");
    }
    
    @Override
    public void delete(String firewallId) throws InternalException, CloudException {
    	/** Does not support delete Firewall */
    	throw new CloudException("No Op");
    }

    /** Equal to network(VLAN) */
    @Override
    public Firewall getFirewall(String firewallId) throws InternalException, CloudException {
     	//Firewall id is the same as network id
        HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.NETWORK_BASE_PATH, null);
    	parameters.put(0, param);
    	param = new Param(firewallId, null);
    	parameters.put(1, param); 
    	
    	OpSourceMethod method = new OpSourceMethod(provider, 
    			provider.buildUrl(null,true, parameters),
    			provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET", null));
      	Document doc = method.invoke();
     
      	Node item = doc.getDocumentElement();
        String sNS = "";
        try{
            sNS = item.getNodeName().substring(0, item.getNodeName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}
      	if(item.getNodeName().equals(sNS + "Network")){
      		return toFirewall(item);   		
      	}
      	return null;        
    }
    private String getOpSourceRuleIdFromDaseinRuleId(@Nonnull String daseinRuleId){
    	if(daseinRuleId.contains(":")){
    		return daseinRuleId.substring(0, daseinRuleId.indexOf(":"));
    		
    	}else{
    		return daseinRuleId;
    	}		
    }
    private String getFirewallPositionIdFromDaseinRuleId(String daseinRuleId){
    	if(daseinRuleId.contains(":")){
    		return daseinRuleId.substring(daseinRuleId.indexOf(":")+1);
    	}else{
    		return null;
    	}
    }
    
    private String getFirstAvaiablePositionForInsertRule(String firewallId) throws InternalException, CloudException{
    	ArrayList<FirewallRule> list = (ArrayList<FirewallRule>) getRules(firewallId);
    	if(list == null){
    		return null;
    	}
    	
    	for(int i = 100;i<= 500;i ++){
    		String position = String.valueOf(i);
    		boolean isExist = false;
    		for(FirewallRule rule: list){
    			if(position.equals(getFirewallPositionIdFromDaseinRuleId(rule.getProviderRuleId()))){
    				isExist = true;
    				break;
    			}       		
        	}
    		if(!isExist){
    			return position;
    		}
    	}
    	return null;
        
    }

    @Override
    public @Nonnull String getProviderTermForFirewall(@Nonnull Locale locale) {
        return "Network group";
    }

    @Override
    public @Nonnull Collection<FirewallRule> getRules(@Nonnull String firewallId) throws InternalException, CloudException {
     	/** In OpSource firewallId is the same as networkId */
 
    	ArrayList<FirewallRule> list = new ArrayList<FirewallRule>();
     
      	HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.NETWORK_BASE_PATH, null);
    	parameters.put(0, param);
    	        	
    	param = new Param(firewallId, null);
      	parameters.put(1, param);
      	
      	param = new Param("aclrule", null);
      	parameters.put(2, param);

    	OpSourceMethod method = new OpSourceMethod(provider, 
    			provider.buildUrl(null,true, parameters),
    			provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
      	Document doc = method.invoke();

        String sNS = "";
        try{
            sNS = doc.getDocumentElement().getTagName().substring(0, doc.getDocumentElement().getTagName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}

        NodeList matches = doc.getElementsByTagName(sNS + "AclRule");
        if(matches != null){
            for( int i=0; i<matches.getLength(); i++ ) {
                Node node = matches.item(i);            
                FirewallRule rule = toRule(firewallId,node);                
                if( rule != null ) {
                	list.add(rule);
                }
            }
        }
        return list;
    }

    public boolean isSubscribed() throws CloudException, InternalException {
        return true;
    }
    
    @Override
    public Collection<Firewall> list() throws InternalException, CloudException {
      	//List the network information
    	ArrayList<Firewall> list = new ArrayList<Firewall>();
        HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param("networkWithLocation", null);
    	parameters.put(0, param);

    	param = new Param(provider.getDefaultRegionId(), null);
      	parameters.put(1, param);

    	/*OpSourceMethod method = new OpSourceMethod(provider,
    			provider.buildUrl(null,true, parameters),
    			provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET",null));
      	Document doc = method.invoke();*/
        Document doc = CallCache.getInstance().getAPICall("networkWithLocation", provider, parameters);

        String sNS = "";
        try{
            sNS = doc.getDocumentElement().getTagName().substring(0, doc.getDocumentElement().getTagName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}
        NodeList matches = doc.getElementsByTagName(sNS + "network");
        if(matches != null){
            for( int i=0; i<matches.getLength(); i++ ) {
                Node node = matches.item(i);            
                Firewall firewall = toFirewall(node);                
                if( firewall != null ) {
                	list.add(firewall);
                }
            }
        }
        return list;
    }


   
    @Override
    public @Nonnull String[] mapServiceAction(@Nonnull ServiceAction action) {
        return new String[0];
    }
    
    /**
     * https://<Cloud API URL>/oec/0.9/{org-id}/network/{netid}/aclrule/{acl-id}?delete
    **/

    @Override
    public void revoke(@Nonnull String firewallId, @Nonnull String cidr, @Nonnull Protocol protocol, int beginPort, int endPort) throws CloudException, InternalException {
        revoke(firewallId, Direction.INGRESS, cidr, protocol, beginPort, endPort);
    }

    @Override
    public void revoke(@Nonnull String firewallId, @Nonnull Direction direction, @Nonnull String cidr, @Nonnull Protocol protocol, int beginPort, int endPort) throws CloudException, InternalException {
        FirewallRule rule = null;
        String opSourceCidr = this.convertCidr(cidr);

        for( FirewallRule r : getRules(firewallId) ) {
            if(opSourceCidr == null &&  !r.getCidr().equals(opSourceCidr) ) {
                continue;
            }
            if( !(r.getStartPort() == beginPort) ) {
                continue;
            }
            if( !(r.getEndPort() == endPort) ) {
                continue;
            }
            if( r.getProtocol() != null &&  !r.getProtocol().equals(protocol) ) {
                continue;
            }

            rule = r;
            break;

        }
        if( rule == null ) {
            logger.warn("No such rule for " + firewallId + ": " + cidr + "/" + protocol + "/" + beginPort + "/" + endPort);
            return;
        }

        HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.NETWORK_BASE_PATH, null);
        parameters.put(0, param);

        param = new Param(firewallId, null);
        parameters.put(1, param);

        param = new Param("aclrule", null);
        parameters.put(2, param);

        String ruleId = this.getOpSourceRuleIdFromDaseinRuleId(rule.getProviderRuleId());
        param = new Param(ruleId, null);
        parameters.put(3, param);

        OpSourceMethod method = new OpSourceMethod(provider,
                provider.buildUrl("delete",true, parameters),
                provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET", null));
        method.parseRequestResult("Revoking firewall rule",method.invoke(), "result", "resultDetail");
    }

    @Override
    public boolean supportsRules(@Nonnull Direction direction, boolean inVlan) throws CloudException, InternalException {
        return (Direction.INGRESS.equals(direction) && !inVlan);
    }

    private Firewall toFirewall(Node node) {
        if( node == null ) {
            return null;
        }
        String sNS = "";
        try{
            sNS = node.getNodeName().substring(0, node.getNodeName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}

        NodeList attributes = node.getChildNodes();
        Firewall firewall = new Firewall();
        
        firewall.setActive(true);
        firewall.setAvailable(true);
        firewall.setRegionId(provider.getContext().getRegionId());
        for( int i=0; i<attributes.getLength(); i++ ) {
            Node attribute = attributes.item(i);
            String name = attribute.getNodeName().toLowerCase();
            String value;
            
            if( attribute.getChildNodes().getLength() > 0 ) {
                value = attribute.getFirstChild().getNodeValue();                
            }
            else {
                value = null;
            }
            if( name.equalsIgnoreCase(sNS + "id") ) {
            	firewall.setProviderFirewallId(value);
            	/** The firewall Id is the same as vlan Id */
            	firewall.setProviderVlanId(value);
            }
            else if( name.equalsIgnoreCase(sNS + "name") ) {
            	firewall.setName("enstratus security group for VLan " + value);
            }
            else if( name.equalsIgnoreCase(sNS + "description") ) {
            	firewall.setDescription("enstratus security group for VLan "+ value);
            }
            else if( name.equalsIgnoreCase(sNS + "location") && value != null ) {
            	firewall.setRegionId(value);
            }
           
        }
        if( firewall.getProviderFirewallId() == null ) {
            logger.warn("Discovered firewall " + firewall.getProviderFirewallId() + " with an empty firewall ID");
            return null;
        }
        if( firewall.getName() == null ) {
            firewall.setName(firewall.getProviderFirewallId());
        }
        if( firewall.getDescription() == null ) {
            firewall.setDescription(firewall.getName());
        }
        return firewall;
    }
    
    private FirewallRule toRule(String firewallId, Node node) {
        if( node == null) {
            return null;
        }
        boolean hasSourceIP = false;
        String sNS = "";
        try{
            sNS = node.getNodeName().substring(0, node.getNodeName().indexOf(":") + 1);
        }
        catch(IndexOutOfBoundsException ex){}
        NodeList attributes = node.getChildNodes();
        FirewallRule rule = new FirewallRule();
        
        rule.setFirewallId(firewallId);
        rule.setPermission(Permission.ALLOW);
        rule.setDirection(Direction.INGRESS);
        String basicRuleId = null;
        String positionId = null;
        
        for( int i=0; i<attributes.getLength(); i++ ) {
            Node attribute = attributes.item(i);
            String name = attribute.getNodeName();
            String value;

            if( attribute.getChildNodes().getLength() > 0 ) {
                value = attribute.getFirstChild().getNodeValue();                
            }
            else {
                value = null;
            }

            if( name.equalsIgnoreCase(sNS + "cidr") ) {
                rule.setCidr(value);
            }           
            else if( name.equalsIgnoreCase(sNS + "id") ) {
            	basicRuleId = value;
            	
            	//rule.setProviderRuleId(value);
            }
            else if( name.equalsIgnoreCase(sNS + "name") ) {
                if(!value.startsWith("default"))rule.setCidr(value);//For custom rules the name contains the proper CIDR
            }
            else if( name.equalsIgnoreCase(sNS + "position") ) {
               positionId = value;
            }
            else if( name.equalsIgnoreCase(sNS + "action") ) {
            	
            	if(value.equalsIgnoreCase("deny")){
            		rule.setPermission(Permission.DENY);
            	}else{
            		rule.setPermission(Permission.ALLOW);
            	}                      	
            }
            else if( name.equalsIgnoreCase(sNS + "protocol") ) {
            	
            	if(value.equalsIgnoreCase("TCP")){
            		rule.setProtocol(Protocol.TCP);
            	}else if (value.equalsIgnoreCase("UPD")){
            		rule.setProtocol(Protocol.UDP);
            	}else if (value.equalsIgnoreCase("ICMP") ){
            		rule.setProtocol(Protocol.ICMP);
            	}
                else{
                    //OpSource has a rule with an odd protocol by default that we don't want to add or display
                    return null;
                }
            	
            }
            else if( name.equalsIgnoreCase(sNS + "sourceIpRange") ) {
         		String ipAddress = null;
        		String networkMask = null;
            	NodeList ipAddresses = attribute.getChildNodes();
            	for(int j = 0 ;j < ipAddresses.getLength(); j ++){
            		Node ip = ipAddresses.item(j);
            		if(ip.getNodeType() == Node.TEXT_NODE) continue;
   
            		if(ip.getNodeName().equals(sNS + "ipAddress") && ip.getFirstChild().getNodeValue() != null){
            			ipAddress = ip.getFirstChild().getNodeValue();
                        hasSourceIP = true;
            		}/*else if(ip.getNodeName().equals(sNS + "netmask") && ip.getFirstChild().getNodeValue() != null){
            			networkMask = ip.getFirstChild().getNodeValue();
            		}*///This may have changed in the API but this doesn't exist anymore.
            	}
            	
            	/*if(ipAddress != null){
            		if(networkMask != null){
            			rule.setCidr(ipAddress+ "/" + networkMask);
            		}else{
            			rule.setCidr(ipAddress+ "/" + "255.255.255.254");
            		}            		
            	}*/
            	  
            }
            else if( name.equalsIgnoreCase(sNS + "destinationIpRange") ) {
            	//TODO    
            }
            else if( name.equalsIgnoreCase(sNS + "portRange") ) {
            	NodeList portAttributes  = attribute.getChildNodes();
            	String portType = null;
           		for(int j=0;j<portAttributes.getLength();j++ ){
	           		Node portItem = portAttributes.item(j);
	           		if( portItem.getNodeName().equalsIgnoreCase(sNS + "type") && portItem.getFirstChild().getNodeValue() != null ) {
	           			portType = portItem.getFirstChild().getNodeValue();	           			
	                }
	                else if( portItem.getNodeName().equalsIgnoreCase(sNS + "port1") && portItem.getFirstChild().getNodeValue() != null ) {
	                	rule.setStartPort(Integer.valueOf(portItem.getFirstChild().getNodeValue()));
	                	if(portType.equalsIgnoreCase("EQUAL_TO")){
	                    	rule.setEndPort(Integer.valueOf(portItem.getFirstChild().getNodeValue()));
	                    }
	                }
	                else if( portItem.getNodeName().equalsIgnoreCase(sNS + "port2") && portItem.getFirstChild().getNodeValue() != null ) {
	                	rule.setEndPort(Integer.valueOf(portItem.getFirstChild().getNodeValue()));
	                }	                                     
           		}              	      
            }
            else if( name.equalsIgnoreCase(sNS + "type") ) {
            	if(value != null){
            		if(value.equalsIgnoreCase("INSIDE_ACL")){
            			rule.setDirection(Direction.EGRESS);
            		}else if (value.equalsIgnoreCase("OUTSIDE_ACL")){
            			rule.setDirection(Direction.INGRESS);
            		}else{
            			rule.setDirection(Direction.INGRESS);
            		}
            	}
            }
        }
        if(basicRuleId != null && positionId != null){
        	rule.setProviderRuleId(basicRuleId+ ":" +positionId);
        }else{
        	return null;
        }
        if(rule.getCidr() == null && !hasSourceIP){
        	rule.setCidr("0.0.0.0/0");
        }

        if(rule.getProtocol() == null){
            //OpSource has a rule with an odd protocol by default that we don't want to add or display
            return null;
        }
        System.out.println("RULE CIDR: " + rule.getCidr());
        System.out.println("RULE DIRECTION: " + rule.getDirection());
        return rule;
    }
}
