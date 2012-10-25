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

package org.dasein.cloud.opsource.compute;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;

import org.dasein.cloud.OperationNotSupportedException;
import org.dasein.cloud.Requirement;
import org.dasein.cloud.compute.Platform;
import org.dasein.cloud.compute.Volume;

import org.dasein.cloud.compute.VolumeCreateOptions;
import org.dasein.cloud.compute.VolumeProduct;
import org.dasein.cloud.compute.VolumeSupport;
import org.dasein.cloud.identity.ServiceAction;
import org.dasein.cloud.opsource.OpSource;
import org.dasein.cloud.opsource.OpSourceMethod;
import org.dasein.cloud.opsource.Param;
import org.dasein.util.uom.storage.Gigabyte;
import org.dasein.util.uom.storage.Storage;


public class Volumes implements VolumeSupport {
    //static private final Logger logger = Logger.getLogger(Volumes.class);
  
    private OpSource provider;
    
    Volumes(OpSource provider) {
        this.provider = provider;
    }
    
    @Override
    public void attach(@Nonnull String volumeId, @Nonnull String serverId, @Nonnull String deviceId) throws InternalException, CloudException {
    	//No need for volumeId and deviceId
    	attach(serverId, 10);    	
    }
    
    public void attach(String serverId, int sizeInGb) throws InternalException, CloudException {
    	HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.SERVER_BASE_PATH, null);
     	parameters.put(0, param);
     	param = new Param(serverId, null);
     	parameters.put(1, param);   
    	param = new Param("amount", String.valueOf(sizeInGb));
     	parameters.put(2, param); 
     	
     	OpSourceMethod method = new OpSourceMethod(provider, 
     			provider.buildUrl(null,true, parameters),
     			provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "POST", null));
       	method.requestResult("Attaching disk",method.invoke());
    }


    @Override
    public @Nonnull String create(@Nonnull String snapshotId, int size, @Nonnull String zoneId) throws InternalException, CloudException {
        throw new OperationNotSupportedException("Creating volumes is not supported");
    }

    @Override
    public @Nonnull String createVolume(@Nonnull VolumeCreateOptions options) throws InternalException, CloudException {
        throw new OperationNotSupportedException("Creating volumes is not supported");
    }

    @Override
    public void detach(@Nonnull String volumeId) throws InternalException, CloudException {
    	HashMap<Integer, Param>  parameters = new HashMap<Integer, Param>();
        Param param = new Param(OpSource.SERVER_BASE_PATH, null);
     	parameters.put(0, param);
     	//param = new Param(serverId, null);
     	//parameters.put(1, param);   
    	param = new Param("amount", String.valueOf(10));
     	parameters.put(2, param); 
     	
     	OpSourceMethod method = new OpSourceMethod(provider, 
     			provider.buildUrl(null,true, parameters),
     			provider.getBasicRequestParameters(OpSource.Content_Type_Value_Single_Para, "GET", null));
       	method.requestResult("Attaching disk",method.invoke());
    }

    @Override
    public int getMaximumVolumeCount() throws InternalException, CloudException {
        return 0;
    }

    @Override
    public Storage<Gigabyte> getMaximumVolumeSize() throws InternalException, CloudException {
        return null;
    }

    @Override
    public @Nonnull Storage<Gigabyte> getMinimumVolumeSize() throws InternalException, CloudException {
        return new Storage<Gigabyte>(1, Storage.GIGABYTE);
    }


    @Override
    public @Nonnull String getProviderTermForVolume(@Nonnull Locale locale) {
        return "disk";
    }

  
    
    @Override
    public @Nullable Volume getVolume(@Nonnull String volumeId) throws InternalException, CloudException {
       return null;
    }

    @Override
    public @Nonnull Requirement getVolumeProductRequirement() throws InternalException, CloudException {
        return Requirement.NONE;
    }

    @Override
    public boolean isVolumeSizeDeterminedByProduct() throws InternalException, CloudException {
        return false;
    }


    @Override
    public boolean isSubscribed() throws CloudException, InternalException {
        return false;
    }

    private List<String> unixDeviceIdList    = null;
    private List<String> windowsDeviceIdList = null;
    
    @Override
    public @Nonnull Iterable<String> listPossibleDeviceIds(@Nonnull Platform platform) throws InternalException, CloudException {
        if( platform.isWindows() ) {
            if( windowsDeviceIdList == null ) {
                ArrayList<String> list = new ArrayList<String>();
                
                list.add("hde");
                list.add("hdf");
                list.add("hdg");
                list.add("hdh");
                list.add("hdi");
                list.add("hdj");
                windowsDeviceIdList = Collections.unmodifiableList(list);
            }
            return windowsDeviceIdList;            
        }
        else {
            if( unixDeviceIdList == null ) {
                ArrayList<String> list = new ArrayList<String>();
                
                list.add("/dev/xvdc");
                list.add("/dev/xvde");
                list.add("/dev/xvdf");
                list.add("/dev/xvdg");
                list.add("/dev/xvdh");
                list.add("/dev/xvdi");
                list.add("/dev/xvdj");
                unixDeviceIdList = Collections.unmodifiableList(list);
            }
            return unixDeviceIdList;
        }
    }

    @Override
    public @Nonnull Iterable<VolumeProduct> listVolumeProducts() throws InternalException, CloudException {
        return Collections.emptyList();
    }

    @Override
    public @Nonnull Iterable<Volume> listVolumes() throws InternalException, CloudException {
        return Collections.emptyList();
    }
     
    private Collection<Volume> listVolumes(boolean rootOnly) throws InternalException, CloudException {
        return Collections.emptyList();
    }

 
    @Override
    public @Nonnull String[] mapServiceAction(@Nonnull ServiceAction action) {
        return new String[0];
    }

    @Override
    public void remove(@Nonnull String volumeId) throws InternalException, CloudException {
        // NO-OP
    }  
  
}
