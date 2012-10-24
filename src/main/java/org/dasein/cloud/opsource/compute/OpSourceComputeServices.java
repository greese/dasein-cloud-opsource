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


import org.dasein.cloud.compute.AbstractComputeServices;
import org.dasein.cloud.opsource.OpSource;
import org.dasein.cloud.opsource.compute.ServerImage;

import javax.annotation.Nonnull;

public class OpSourceComputeServices extends AbstractComputeServices {
    private OpSource cloud = null;
    
    public OpSourceComputeServices(@Nonnull OpSource cloud) { this.cloud = cloud; }
    
    @Override
    public @Nonnull ServerImage getImageSupport() {
        return new ServerImage(cloud);
    }

    
    @Override
    public @Nonnull VirtualMachines getVirtualMachineSupport() {
        return new VirtualMachines(cloud);
    }
/*    
    @Override
    public @Nonnull Volumes getVolumeSupport() {
        return new Volumes(cloud);
    }*/
}
