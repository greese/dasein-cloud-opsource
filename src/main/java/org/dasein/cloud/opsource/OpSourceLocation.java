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

package org.dasein.cloud.opsource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;

import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;

import org.dasein.cloud.dc.DataCenter;
import org.dasein.cloud.dc.DataCenterServices;
import org.dasein.cloud.dc.Region;

import org.dasein.cloud.util.APITrace;
import org.dasein.cloud.util.Cache;
import org.dasein.cloud.util.CacheLevel;
import org.dasein.util.uom.time.Day;
import org.dasein.util.uom.time.TimePeriod;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.annotation.Nonnull;

public class OpSourceLocation implements DataCenterServices {
	
	private OpSource provider = null;

	OpSourceLocation(OpSource provider) {
		this.provider = provider;
	}

	@Override
	public DataCenter getDataCenter(String dataCenterId) throws InternalException,CloudException {
        APITrace.begin(provider, "DC.getDataCenter");
        try {
            ArrayList<Region> regions = (ArrayList<Region>) listRegions();
            if( regions == null ) {
                return null;
            }

            for(Region region: regions){
                ArrayList<DataCenter> dataCenters = (ArrayList<DataCenter>) this.listDataCenters(region.getProviderRegionId());

                for(DataCenter dc : dataCenters ){
                    if(dc.getProviderDataCenterId().equals(dataCenterId)){
                        return dc;
                    }
                }
            }
            return null;
        }
        finally {
            APITrace.end();
        }
	}

	@Override
	public String getProviderTermForDataCenter(Locale locale) {
		return "Data Center";
	}

	@Override
	public String getProviderTermForRegion(Locale locale) {
		return "Location";
	}

	@Override
	public Region getRegion(String regionId) throws InternalException,CloudException {
        APITrace.begin(provider, "DC.getRegion");
        try {
            ArrayList<Region> regions = (ArrayList<Region>) listRegions();
            if(regions != null){
                for(Region region: regions){
                    if(regionId.equals(region.getProviderRegionId())){
                        return region;
                    }
                }
            }
            return null;
        }
        finally {
            APITrace.end();
        }
	}

	@Override
	public @Nonnull Collection<DataCenter> listDataCenters(@Nonnull String regionId)throws InternalException, CloudException {
        APITrace.begin(provider, "DC.listDataCenters");
        try {
            Region region = this.getRegion(regionId);
            if(region == null){
                throw new CloudException("No such region with regionId -> " + regionId);
            }

            DataCenter dc = new DataCenter();
            dc.setActive(true);
            dc.setAvailable(true);
            dc.setName(region.getName() + " (DC)");
            dc.setRegionId(regionId);
            dc.setProviderDataCenterId(regionId);

            return Collections.singletonList(dc);
        }
        finally {
            APITrace.end();
        }
	}

	@Override
	public Collection<Region> listRegions() throws InternalException,CloudException {
        APITrace.begin(provider, "DC.listRegions");
        try {
            Cache<Region> cache = Cache.getInstance(provider, "regions", Region.class, CacheLevel.CLOUD_ACCOUNT, new TimePeriod<Day>(1, TimePeriod.DAY));
            Collection<Region> cached = (Collection<Region>)cache.get(provider.getContext());

            if( cached != null ) {
                return cached;
            }
            ArrayList<Region> list = new ArrayList <Region>();

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
            catch(IndexOutOfBoundsException ignore){
                //ignore
            }
            NodeList blocks = doc.getElementsByTagName(sNS + "datacenterWithLimits");
            if(blocks != null){
                for(int i=0; i< blocks.getLength();i++){
                    Node item = blocks.item(i);
                    Region region = toRegion(item, sNS);
                    if(region != null){
                        list.add(region);
                    }
                }
            }
            cache.put(provider.getContext(), list);
            return list;
        }
        finally {
            APITrace.end();
        }
	}

	private Region toRegion( Node region, String nameSpace) throws CloudException{
		if(region == null){
			return null;
		}
		
		NodeList data;
    	
		data = region.getChildNodes();
		
		Region r = new Region();
		for( int i=0; i<data.getLength(); i++ ) {
			Node item = data.item(i);
            if( item.getNodeType() == Node.TEXT_NODE ) {
                continue;
            }
			
			if( item.getNodeName().equals(nameSpace + "location") ) {
				r.setProviderRegionId(item.getFirstChild().getNodeValue());
			}
			else if( item.getNodeName().equals(nameSpace + "displayName") ) {
				r.setName(item.getFirstChild().getNodeValue());
			}
		}	
		r.setActive(true);
		r.setAvailable(true);
		String host = provider.getEndpointURL().getHost();
		
		if(  host.contains("eu")) {
		    r.setJurisdiction("EU");
		}
		else if( host.contains("au") ) {
		    r.setJurisdiction("AU");
		}
		else if( host.contains("af") ) {
		    r.setJurisdiction("ZA");
		}
		else  {
		    r.setJurisdiction("US");
		}
		return r;
	}
}
