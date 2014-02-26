/*
 * Copyright (C) 2013 .
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author:
 *   Changyao Han <changyaoh@gmail.com>
 *   
 *   Based on security_selinux.c by James Morris <jmorris@namei.org>
 *   and security_apparmor.c by Jamie Strandboge <jamie@canonical.com>
 *
 *   Smack scurity driver.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <attr/xattr.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <errno.h>
#include <unistd.h>
#include <wait.h>
#include <dirent.h>
#include <stdlib.h>


#include "security_smack.h"
#include "virerror.h"
#include "viralloc.h"
#include "datatypes.h"
#include "viruuid.h"
#include "virlog.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virstoragefile.h"
#include "virfile.h"
#include "configmake.h"
#include "vircommand.h"
#include "virhash.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY
#define SECURITY_SMACK_VOID_DOI     "0"
#define SECURITY_SMACK_NAME         "smack"

/*
 *
 *typedef struct _SmackCallbackData SmackCallbackData; 
 *typedef SmackCallbackData *SmackCallbackDataPtr;
 *
 *struct _SmackCallbackData {
 *     virSecurityManagerPtr manager;
 *     virSecurityLabelDefPtr secdef;
 *};
 */

static char *
get_label_name(virDomainDefPtr def)
{
	char uuidstr[VIR_UUID_STRING_BUFLEN];
	char *name = NULL;

	virUUIDFormat(def->uuid,uuidstr);
	if(virAsprintf(&name,"%s%s",SMACK_PREFIX,uuidstr) < 0)
		return NULL;

	return name;
}


int getfilelabel(const char *path, char ** label)
{
	char *buf;
	ssize_t size;
	ssize_t ret;

	size = SMACK_LABEL_LEN + 1;
	buf = malloc(size);
        if(!buf)
		return -1;
	memset(buf,0,size);

	ret = getxattr(path,"security.SMACK64", buf, size - 1);
	if (ret < 0 && errno == ERANGE) {
		char *newbuf;

		size = getxattr(path,"security.SMACK64", NULL, 0);
		if(size < 0)
			goto out;

		size++;
		newbuf = realloc(buf,size);
		if(!newbuf)
			goto out;

		buf = newbuf;
		memset(buf,0,size);
		ret = getxattr(path,"security.SMACK64",buf,size - 1);
	}
     out:
	if (ret == 0) {
		 /* Re-map empty attribute values to errors. */
                  errno = ENOTSUP;
                  ret = -1;
	}
	if (ret < 0)
		free(buf);
	else
		*label = buf;
	return ret;
}

int setfilelabel(const char *path,const char * label)
{
  int ret = setxattr(path,"security.SMACK64",label,strlen(label)+ 1,0);
   
  if (ret < 0 && errno == ENOTSUP) {
	  char * clabel = NULL;
	  int err = errno;
	  if ((getfilelabel(path,&clabel) >= 0) &&
	      (strcmp(label,clabel) == 0)) {
		  ret = 0;
	  }else{
		  errno = err;
	  }
	  free(clabel);
  }
  return ret;
 
}


int fgetfilelabel(int fd,char ** label)
{
	char *buf;
	ssize_t size;
	ssize_t ret;

	size = SMACK_LABEL_LEN + 1;
	buf = malloc(size);
        if(!buf)
		return -1;
	memset(buf,0,size);

	ret = fgetxattr(fd,"security.SMACK64", buf, size - 1);
	if (ret < 0 && errno == ERANGE) {
		char *newbuf;

		size = fgetxattr(fd,"security.SMACK64", NULL, 0);
		if(size < 0)
			goto out;

		size++;
		newbuf = realloc(buf,size);
		if(!newbuf)
			goto out;

		buf = newbuf;
		memset(buf,0,size);
		ret = fgetxattr(fd,"security.SMACK64",buf,size - 1);
	}
     out:
	if (ret == 0) {
		 /* Re-map empty attribute values to errors. */
                  errno = ENOTSUP;
                  ret = -1;
	}
	if (ret < 0)
		free(buf);
	else
		*label = buf;
	return ret;
}

int fsetfilelabel(int fd,const char * label)
{
  int ret = fsetxattr(fd,"security.SMACK64",label,strlen(label)+ 1,0);
   
  if (ret < 0 && errno == ENOTSUP) {
	  char * clabel = NULL;
	  int err = errno;
	  if ((fgetfilelabel(fd,&clabel) >= 0) &&
	      (strcmp(label,clabel) == 0)) {
		  ret = 0;
	  }else{
		  errno = err;
	  }
	  free(clabel);
  }
  return ret;
}

static int getpidlabel(pid_t pid,char **label)
{

        char *result;
        int fd;
        int ret;
        char *path;

        result = calloc(SMACK_LABEL_LEN + 1,1);
        if(result == NULL)
	    return -1;
        ret = virAsprintf(&path,"/proc/%d/attr/current",pid);
        if (ret < 0)
	    return -1;
        fd = open(path,O_RDONLY);
        VIR_FREE(path);
        if (fd < 0){
	    free(result);
	    return -1;
        }
        ret = read(fd,result,SMACK_LABEL_LEN);
        close(fd);
        if(ret < 0){
	    free(result);
	    return -1;
        }
        *label = result;
        return ret;

}
	 
	 

int setsockcreate(const char *label,const char *attr)
{
        int fd;
        int ret = -1;
	long int tid;
        char *path;
	tid = syscall(SYS_gettid);
        ret = virAsprintf(&path,"/proc/self/task/%ld/attr/%s",tid,attr);
        if (ret < 0)
	    return -1;

    VIR_DEBUG("setsockcreate pid is in %d",getpid());
    VIR_DEBUG("real user ID is in %d",getuid());
    VIR_DEBUG("effective user ID is in %d",geteuid());
    VIR_DEBUG("label from self %s",label);
    VIR_DEBUG("location /proc/self/attr/%s",attr);
       
        if (label){
                    fd = open(path,O_WRONLY | O_CLOEXEC);
		    VIR_DEBUG("open file %s",path);
                    VIR_FREE(path);
                    if (fd < 0)
		    {
		    VIR_DEBUG("open faile");
	                  return -1;
		    }
		    VIR_DEBUG("open success");
		do {
                      ret = write(fd,label,strlen(label) + 1);
		}while(ret < 0 && errno == EINTR);
	}
	else { 
                    fd = open(path,O_TRUNC);
                    VIR_FREE(path);
                    if (fd < 0)
	                  return -1;
		    ret = 0;
	}
  
        close(fd);

        return (ret < 0) ? -1 : 0;

}



/*
 *
 *
 *static int
 *setselfsocklabel(const char * conname,const char * smacklabel)
 *{
 *
 *    int ret = -1;
 *    int sfd;
 *    DIR *dp;
 *    struct dirent *files;
 *    struct stat buf;
 *
 *    if((dp = opendir("/proc/self/fd")) == NULL)
 *            return -1;
 *
 *    while((files = readdir(dp))!=NULL)
 *    {
 *            if(!strcmp(files->d_name,".") || !strcmp(files->d_name,".."))
 *                    continue;
 *
 *            sfd = atoi(files->d_name);
 *
 *            if(fstat(sfd,&buf) == -1)
 *                    goto done;
 *
 *            if(S_ISSOCK(buf.st_mode))
 *            {
 *               if(fsetxattr(sfd,conname,smacklabel,strlen(smacklabel)+ 1,0)< 0)
 *                    goto done;
 *
 *            }
 *    }
 *
 *    ret = 0;
 *
 *done:
 *    return ret;
 *
 *}
 *
 */


static int
SmackSetFileLabelHelper(const char *path, const char *tlabel)
{
   char * elabel = NULL;
   
   VIR_INFO("Setting Smack label on '%s' to '%s'", path, tlabel);

       if (setfilelabel(path, tlabel) < 0) {
	   int setfilelabel_errno = errno;

	   if (getfilelabel(path, &elabel) >= 0) {
	       if (STREQ(tlabel, elabel)) {
	           free(elabel);
       /* It's alright, there's nothing to change anyway. */
		   return 0;
	   }
	   free(elabel);
       }

       /* if the error complaint is related to an image hosted on
        * an nfs mount, or a usbfs/sysfs filesystem not supporting
        * labelling, then just ignore it & hope for the best.
        */

       if (setfilelabel_errno != EOPNOTSUPP && setfilelabel_errno != ENOTSUP) {
	   virReportSystemError(setfilelabel_errno,
	                        _("unable to set security context '%s' on '%s'"),
	                        tlabel, path);
	       return -1;

       } else {
	        const char *msg;
		if ((virStorageFileIsSharedFSType(path, VIR_STORAGE_FILE_SHFS_NFS) == 1)) { 
                    msg = _("Setting security context '%s' on '%s' not supported. ");
                    VIR_WARN(msg, tlabel, path);
        	} else { 
                    VIR_INFO("Setting security context '%s' on '%s' not supported",tlabel,path );

         	} 

      }

   }
   return 0;

}

static int
SmackSetFileLabel(const char *path,const char *label)
{
   return SmackSetFileLabelHelper(path,label);
}



static int
SmackSetSecurityHostdevLabelHelper(const char *file,void *opaque)
{
    virSecurityLabelDefPtr seclabel;
    virDomainDefPtr def = opaque;

    seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	return -1;
    return SmackSetFileLabel(file, seclabel->imagelabel);
}


static int
SmackSetSecurityUSBLabel(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
		         const char *file, void *opaque)
{
    return SmackSetSecurityHostdevLabelHelper(file,opaque);
}


static int
SmackSetSecurityPCILabel(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
		         const char *file, void *opaque)
{
    return SmackSetSecurityHostdevLabelHelper(file, opaque);
}

static int
SmackSetSecuritySCSILabel(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
		          const char *file, void *opaque)
{
    return SmackSetSecurityHostdevLabelHelper(file, opaque);
}


static int
SmackRestoreSecurityFileLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		              const char *path)
{
      struct stat buf;
      int ret = -1;
      char *newpath = NULL;
      char ebuf[1024];

      VIR_INFO("Restoring Smack label on '%s'", path);

      if (virFileResolveLink(path, &newpath) < 0) {
             VIR_WARN("cannot resolve symlink %s: %s", path,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
             goto err;
     }

      if (stat(newpath, &buf) != 0) {
          VIR_WARN("cannot stat %s: %s", newpath,
                   virStrerror(errno, ebuf, sizeof(ebuf)));
          goto err;
     }

      ret = SmackSetFileLabel(newpath,"smack-unused");

	  /*
           *ret = setxattr(def->disks[i]->src,"security.SMACK64","smack-unused",strlen("smack-unused") + 1,0);
	   */
err:
     VIR_FREE(newpath);
     return ret;
}


static int
SmackRestoreSecurityUSBLabel(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
		             const char *file,
			     void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return SmackRestoreSecurityFileLabel(mgr,file);
}

static int
SmackRestoreSecurityPCILabel(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
		             const char *file,
			     void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return SmackRestoreSecurityFileLabel(mgr,file);
}

static int
SmackRestoreSecuritySCSILabel(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
		              const char *file,
			      void *opaque)
{
     virSecurityManagerPtr mgr = opaque;

    return SmackRestoreSecurityFileLabel(mgr,file);
}





static int
SmackRestoreSecurityImageLabelInt(virSecurityManagerPtr mgr,
		                  virDomainDefPtr def,
				  virDomainDiskDefPtr disk,
				  int migrated)
{
	virSecurityLabelDefPtr seclabel;

	seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);

        if (seclabel == NULL)
		return -1;

	if (seclabel->norelabel) 
		return 0;

	if (disk->readonly || disk->shared)
		return 0;

	if (!disk->src || disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK)
		return 0;

	if (migrated) {
	    int ret = virStorageFileIsSharedFS(disk->src);
	    if (ret < 0)
	        return -1;
	    if (ret == 1) {
	        VIR_DEBUG("Skipping image label restore on %s because FS is shared",disk->src);
                return 0;
            }

        }

	return SmackRestoreSecurityFileLabel(mgr,disk->src);

      /*
       *return setxattr(def->disks[i]->src,"security.SMACK64","smack-unused",strlen("smack-unused") + 1,0);
       */

}



static int
SmackFSetFileLabel(int fd,char *tlabel)
{
     char *elabel = NULL;

     VIR_INFO("Setting Smack label on fd %d to '%s'",fd,tlabel);

     if (fsetfilelabel(fd,tlabel) < 0) {
	 int fsetfilelabel_errno = errno;
      
         if (fgetfilelabel(fd,&elabel) >= 0) {
	     if(STREQ(tlabel,elabel)) {
		     free(elabel);
                  /* It's alright, there's nothing to change anyway. */
		  
		     return 0;
	     }

	     free(elabel);
	 }
       /* if the error complaint is related to an image hosted on
        * an nfs mount, or a usbfs/sysfs filesystem not supporting
        * labelling, then just ignore it & hope for the best.
        */
        if (fsetfilelabel_errno != EOPNOTSUPP) {
             virReportSystemError(fsetfilelabel_errno,
   		                  _("unable to set security context '%s' on fd %d"), tlabel, fd);
               return -1;
         } else {
            VIR_INFO("Setting security label '%s' on fd %d not supported",
	              tlabel, fd);
         }
     }
     return 0;
}


static int
SmackSetSecurityHostdevSubsysLabel(virDomainDefPtr def,
		                   virDomainHostdevDefPtr dev,
				   const char *vroot)
{
    int ret = -1;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(dev->source.subsys.u.usb.bus,
                              dev->source.subsys.u.usb.device,
                              vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, SmackSetSecurityUSBLabel, def);
        virUSBDeviceFree(usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                            dev->source.subsys.u.pci.addr.bus,
                            dev->source.subsys.u.pci.addr.slot,
                            dev->source.subsys.u.pci.addr.function);

        if (!pci)
            goto done;

        if (dev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                goto done;
            }
            ret = SmackRestoreSecurityPCILabel(pci, vfioGroupDev, def);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, SmackSetSecurityPCILabel, def);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(dev->source.subsys.u.scsi.adapter,
                             dev->source.subsys.u.scsi.bus,
                             dev->source.subsys.u.scsi.target,
                             dev->source.subsys.u.scsi.unit,
                             dev->readonly);

            if (!scsi)
                goto done;

            ret = virSCSIDeviceFileIterate(scsi, SmackSetSecuritySCSILabel, def);
            virSCSIDeviceFree(scsi);

            break;
       }

    default:
        ret = 0;
        break;
    }

done:
    return ret;
}

static int
SmackSetSecurityHostdevCapsLabel(virDomainDefPtr def,
		                 virDomainHostdevDefPtr dev,
				 const char *vroot)
{
    int ret = -1;
    virSecurityLabelDefPtr seclabel;
    char *path;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
        return -1;

    switch (dev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE: {
        if (vroot) {
            if (virAsprintf(&path, "%s/%s", vroot,
                            dev->source.caps.u.storage.block) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(path, dev->source.caps.u.storage.block) < 0)
                return -1;
        }
        ret = SmackSetFileLabel(path, seclabel->imagelabel);
        VIR_FREE(path);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC: {
        if (vroot) {
            if (virAsprintf(&path, "%s/%s", vroot,
                            dev->source.caps.u.misc.chardev) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(path, dev->source.caps.u.misc.chardev) < 0)
                return -1;
        }
        ret = SmackSetFileLabel(path, seclabel->imagelabel);
        VIR_FREE(path);
        break;
    }

    default:
        ret = 0;
        break;
    }

    return ret;

}

static int
SmackRestoreSecurityHostdevSubsysLabel(virSecurityManagerPtr mgr,
		                       virDomainHostdevDefPtr dev,
				       const char *vroot)
{
    int ret = -1;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(dev->source.subsys.u.usb.bus,
                              dev->source.subsys.u.usb.device,
                              vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, SmackRestoreSecurityUSBLabel, mgr);
        virUSBDeviceFree(usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                            dev->source.subsys.u.pci.addr.bus,
                            dev->source.subsys.u.pci.addr.slot,
                            dev->source.subsys.u.pci.addr.function);

        if (!pci)
            goto done;

        if (dev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                goto done;
            }
            ret = SmackRestoreSecurityPCILabel(pci, vfioGroupDev, mgr);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, SmackRestoreSecurityPCILabel, mgr);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(dev->source.subsys.u.scsi.adapter,
                             dev->source.subsys.u.scsi.bus,
                             dev->source.subsys.u.scsi.target,
                             dev->source.subsys.u.scsi.unit,
                             dev->readonly);

            if (!scsi)
                goto done;

            ret = virSCSIDeviceFileIterate(scsi, SmackRestoreSecuritySCSILabel, mgr);
            virSCSIDeviceFree(scsi);

            break;
       }

    default:
        ret = 0;
        break;
    }

done:
    return ret;

}



static int
SmackRestoreSecurityHostdevCapsLabel(virSecurityManagerPtr mgr,
				     virDomainHostdevDefPtr dev,
				     const char *vroot)
{
    int ret = -1;
    char *path;

    switch (dev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE: {
        if (vroot) {
            if (virAsprintf(&path, "%s/%s", vroot,
                            dev->source.caps.u.storage.block) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(path, dev->source.caps.u.storage.block) < 0)
                return -1;
        }
        ret = SmackRestoreSecurityFileLabel(mgr, path);
        VIR_FREE(path);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC: {
        if (vroot) {
            if (virAsprintf(&path, "%s/%s", vroot,
                            dev->source.caps.u.misc.chardev) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(path, dev->source.caps.u.misc.chardev) < 0)
                return -1;
        }
        ret = SmackRestoreSecurityFileLabel(mgr, path);
        VIR_FREE(path);
        break;
    }

    default:
        ret = 0;
        break;
    }

    return ret;
}


/*Called on libvirtd startup to see if Smack is available*/
static int
SmackSecurityDriverProbe(const char *virtDriver)
{
	if(!smack_smackfs_path())
		return SECURITY_DRIVER_DISABLE;
        if (virtDriver && STREQ(virtDriver, "LXC")) {
#if HAVE_SELINUX_LXC_CONTEXTS_PATH
           if (!virFileExists(selinux_lxc_contexts_path()))
#endif
        return SECURITY_DRIVER_DISABLE;
        }

	return SECURITY_DRIVER_ENABLE;

}

/*Security dirver initialization .*/
static int
SmackSecurityDriverOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
	return 0;
}

static int
SmackSecurityDriverClose(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
	return 0;
}

static const char *
SmackSecurityDriverGetModel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
	return SECURITY_SMACK_NAME;
}

static const char *
SmackSecurityDriverGetDOI(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
	return SECURITY_SMACK_VOID_DOI;
}

static int
SmackSecurityVerify(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		    virDomainDefPtr def)
{
        virSecurityLabelDefPtr seclabel;        
        seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
	if (seclabel == NULL)
		return -1;

	if (!STREQ(SECURITY_SMACK_NAME, seclabel->model)) {
	    virReportError(VIR_ERR_INTERNAL_ERROR,
	                   _("security label driver mismatch: "
	                     "'%s' model configured for domain, but "
	                     "hypervisor driver is '%s'."),
	                    seclabel->model, SECURITY_SMACK_NAME);
	        return -1;
	}

	if(seclabel->type == VIR_DOMAIN_SECLABEL_STATIC){
       	   if (smack_label_length(seclabel->label) < 0) {
	    virReportError(VIR_ERR_XML_ERROR,
			   _("Invalid security label %s"), seclabel->label);
		return -1;
	   }
	}

    return 0;

}


static int
SmackSetSecurityImageLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
			   virDomainDefPtr def,
			   virDomainDiskDefPtr disk)
{
	virSecurityLabelDefPtr seclabel;
	seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);

	if (seclabel == NULL)
	    return -1;

	if (seclabel->norelabel)
	    return 0;

	if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK)
	    return 0;

   VIR_DEBUG("set disk image security label before");

        if (setxattr(disk->src,"security.SMACK64",seclabel->imagelabel,strlen(seclabel->imagelabel) + 1,0)< 0)
	    return -1;

   VIR_DEBUG("disk image %s",disk->src);
   VIR_DEBUG("set disk image security label after");

	return 0;

}

static int
SmackRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
			   virDomainDefPtr def,
			   virDomainDiskDefPtr disk)
{
     return SmackRestoreSecurityImageLabelInt(mgr, def,disk,0);

}

/*
 *
 *static int
 *SmackSetSecurityDaemonSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,virDomainDefPtr def)
 *{
 *
 *    virSecurityLabelDefPtr seclabel;
 *
 *    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
 *    if (seclabel == NULL)
 *        return -1;
 *
 *    if (seclabel->label == NULL)
 *        return 0;
 *
 *    if (!STREQ(SECURITY_SMACK_NAME, seclabel->model)) {
 *        virReportError(VIR_ERR_INTERNAL_ERROR,
 *                       _("security label driver mismatch: "
 *                         "'%s' model configured for domain, but "
 *                         "hypervisor driver is '%s'."),
 *                       seclabel->model, SECURITY_SMACK_NAME);
 *        return -1;
 *    }
 *
 *
 *    VIR_DEBUG("Setting VM %s socket context %s", def->name, seclabel->label);
 *    if (setselfsocklabel("security.SMACK64IPIN",seclabel->label) == -1) {
 *        virReportSystemError(errno,
 *                             _("unable to set socket smack label '%s'"), seclabel->label);
 *        return -1;
 *    }
 *
 *    return 0;
 *}
 *
 */

static int
SmackSetSecurityDaemonSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED, virDomainDefPtr vm)
{


	//return 0;

    virSecurityLabelDefPtr seclabel;  
    char *label = NULL;
    int ret = -1;

    seclabel = virDomainDefGetSecurityLabelDef(vm, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	return -1;

    if (seclabel->label == NULL)
	return 0;

    if (!STREQ(SECURITY_SMACK_NAME, seclabel->model)) {
	virReportError(VIR_ERR_INTERNAL_ERROR,
		       _("security label driver mismatch: "
			 "'%s' model configured for domain, but "
			 "hypervisor driver is '%s'."),
		       seclabel->model, SECURITY_SMACK_NAME);
	    return -1;
    }

    if (smack_new_label_from_self(&label) == -1){
	virReportSystemError(errno,
			     _("unable to get current process context '%s'"), seclabel->label);
	 goto done; 
    }
	
    VIR_DEBUG("SmackSetSecurityDaemonSocketLabel is in %d",getpid());
    VIR_DEBUG("label from self %s",label);

    
    VIR_DEBUG("Setting VM %s socket label %s", vm->name, seclabel->label);
    if (setsockcreate(seclabel->label,"sockincreate") == -1) {
	virReportSystemError(errno,
			     _("unable to set socket smack label '%s'"), seclabel->label);
	 goto done; 
    }

    ret = 0;
done:

    free(label);
    return ret;
    
}



static int
SmackSetSecuritySocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		            virDomainDefPtr vm)
{

    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(vm, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	return -1;

    if (seclabel->label == NULL)
	return 0;

    if (!STREQ(SECURITY_SMACK_NAME, seclabel->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       seclabel->model, SECURITY_SMACK_NAME);
            return -1;
    }

    VIR_DEBUG("Setting VM %s socket label %s", vm->name, seclabel->label);

    if (setsockcreate(seclabel->label,"sockoutcreate") == -1) {
        virReportSystemError(errno,
                             _("unable to set socket smack label '%s'"),
                             seclabel->label);
            return -1; 
    }


    return 0;
    
}


static int
SmackClearSecuritySocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		              virDomainDefPtr def)
{

    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
        return -1;

    if (seclabel->label == NULL)
        return 0;

    if (!STREQ(SECURITY_SMACK_NAME, seclabel->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       seclabel->model, SECURITY_SMACK_NAME);
            return -1;
    }

    VIR_DEBUG("clear sock label");

    if (setsockcreate(NULL,"sockincreate") == -1 || setsockcreate(NULL,"sockoutcreate") == -1) {
        virReportSystemError(errno,
                             _("unable to clear socket smack label '%s'"),
                             seclabel->label);

            return -1;
    } 

    return 0;
}



/*
 *Current called in qemuStartVMDaemon to setup a 'label'. We make the 
 *label based on UUID.
 *this is called on 'start'with RestoreSecurityLabel being called on 
 *shutdown
 */

static int
SmackGenSecurityLabel(virSecurityManagerPtr mgr,
		      virDomainDefPtr def)
{
    int ret = -1;
    char *label_name = NULL;
    virSecurityLabelDefPtr seclabel; 
    
    seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);
    if(seclabel == NULL)
	    return ret;
    
    VIR_DEBUG("label=%s",virSecurityManagerGetDriver(mgr));
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        seclabel->label) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security label already defined for VM"));
        return ret;
    }    

    if (seclabel->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security image label already defined for VM"));
        return ret;
    } 

    if (seclabel->model &&
        STRNEQ(seclabel->model, SECURITY_SMACK_NAME)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label model %s is not supported with smack"),
                       seclabel->model);
         return ret;
    }

    VIR_DEBUG("type=%d", seclabel->type);

    if ((label_name = get_label_name(def)) == NULL)
	 return ret;
   
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC){

        /*set process label*/
       if (VIR_STRDUP(seclabel->label,label_name) < 0)
	 goto cleanup;
    }

    /*set imagelabel the same as label*/
    if (VIR_STRDUP(seclabel->imagelabel,label_name) < 0)
	 goto cleanup;
    
    if (!seclabel->model &&
        VIR_STRDUP(seclabel->model, SECURITY_SMACK_NAME) < 0)
         goto cleanup;

    ret = 0;

cleanup:

    if(ret != 0){
       if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC)
           VIR_FREE(seclabel->label);
	   VIR_FREE(seclabel->imagelabel);
       if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
           !seclabel->baselabel)
	   VIR_FREE(seclabel->model);
    }

    VIR_FREE(label_name);

    VIR_DEBUG("model=%s label=%s imagelabel=%s",
              NULLSTR(seclabel->model),
              NULLSTR(seclabel->label),
              NULLSTR(seclabel->imagelabel));
    
    return ret;

}



static int
SmackReserveSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	                  virDomainDefPtr def ATTRIBUTE_UNUSED,
	                  pid_t pid ATTRIBUTE_UNUSED)
{
       /*Security label is based UUID,*/
	return 0;
}

/*
 *Called on VM shutdown and destroy.
 */

static int
SmackReleaseSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		          virDomainDefPtr def)
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	    return -1;

    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(seclabel->label);
        VIR_FREE(seclabel->model);
    }
    VIR_FREE(seclabel->imagelabel);

    return 0;

}



/* Seen with 'virsh dominfo <vm>'. This function only called if the VM is
 * running.
 */
static int
SmackGetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	                     virDomainDefPtr def ATTRIBUTE_UNUSED,
	                     pid_t pid,
			     virSecurityLabelPtr sec)
{

	 char *label_name = NULL;

	 if (getpidlabel(pid,&label_name) == -1){
             virReportSystemError(errno,
	                        _("unable to get PID %d security label"),
	                        pid);
             return -1;
	 }

	 if (strlen(label_name) >= VIR_SECURITY_LABEL_BUFLEN ){
    	     virReportError(VIR_ERR_INTERNAL_ERROR,
	                    _("security label exceeds "
	                      "maximum length: %d"),
	                    VIR_SECURITY_LABEL_BUFLEN - 1);
	     free(label_name);
	     return -1; 
	 }

         strcpy(sec->label,label_name);
	 free(label_name);
	 /*Smack default enforced*/
	 sec->enforcing = 1;

	 return 0;
}


static int
SmackSetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	                     virDomainDefPtr def)
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);

    if (seclabel == NULL)
        return -1;

    if (seclabel->label == NULL)
        return 0;

    if (STRNEQ(SECURITY_SMACK_NAME, seclabel->model)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("security label driver mismatch: "
                        "\'%s\' model configured for domain, but "
                        "hypervisor driver is \'%s\'."),
                      seclabel->model, SECURITY_SMACK_NAME);

               return -1;
	}

    if (smack_set_label_for_self(seclabel->label) < 0) {
	 virReportError(errno,
		        _("unable to set security label '%s'"),
		        seclabel->label);
	    
	    return -1;
        }

    return 0;

}



static int
SmackSetSecurityChildProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED, 
	                   	  virDomainDefPtr def,
				  virCommandPtr cmd)
{
       virSecurityLabelDefPtr seclabel;

       seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);

       if (seclabel == NULL)
	   return -1;

       if (seclabel->label == NULL)
	   return 0;

       if (STRNEQ(SECURITY_SMACK_NAME, seclabel->model)) {
           virReportError(VIR_ERR_INTERNAL_ERROR,
                          _("security label driver mismatch: "
                            "\'%s\' model configured for domain, but "
                            "hypervisor driver is \'%s\'."),
                          seclabel->model, SECURITY_SMACK_NAME);

	   return -1;
       }

       /*
        *if ((label_name = get_label_name(def)) == NULL)
	*    goto cleanup;
	*/

    /* save in cmd to be set after fork/before child process is exec'ed */
       virCommandSetSmackLabel(cmd,seclabel->label);
       VIR_DEBUG("save smack label in cmd %s",seclabel->label);

       return 0;

}



static int
SmackSetSecurityAllLabel(virSecurityManagerPtr mgr,
		         virDomainDefPtr def,
			 const char *stdin_path)
{

   size_t i;
   virSecurityLabelDefPtr seclabel;

   seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);

   if (seclabel == NULL)
	   return -1;

   if (seclabel->norelabel)
	   return 0;
    
   VIR_DEBUG("set image security label before");

   /*
    *for (i = 0; i < def->ndisks; i++) {
    *    if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_DIR) {
    *        VIR_WARN("Unable to relabel directory tree %s for disk %s",
    *                 def->disks[i]->src, def->disks[i]->dst);
    *        continue;
    *    }
    */

   VIR_DEBUG("set image security label");

       if (SmackSetSecurityImageLabel(mgr,
			       def,def->disks[0]) < 0)
	   return -1;
    /*
     *}
     */

   VIR_DEBUG("set image security label after");

   if (stdin_path) {
       if (setxattr(def->disks[i]->src,"security.SMACK64",seclabel->imagelabel,strlen(seclabel->imagelabel) + 1,0)< 0 &&
           virStorageFileIsSharedFSType(stdin_path,
                                        VIR_STORAGE_FILE_SHFS_NFS) != 1)
           return -1;
    }

    return 0;

}

static int
SmackRestoreSecurityAllLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr def,
                             int migrated ATTRIBUTE_UNUSED)
{
   size_t i;
   virSecurityLabelDefPtr seclabel;

   VIR_DEBUG("Restoring security label on %s", def->name);

   seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);

   if (seclabel == NULL)
	   return -1;

   if (seclabel->norelabel)
	   return 0;

   for (i = 0; i < def->ndisks; i++) {

      if (SmackRestoreSecurityImageLabelInt(mgr,
			                    def,
					    def->disks[i],
					    migrated) < 0)
      /*if (setxattr(def->disks[i]->src,"security.SMACK64","smack-unused",strlen("smack-unused"),0)< 0)*/

        return -1;

   }

   return 0;   

}



static int
SmackSetSecurityHostdevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		             virDomainDefPtr def,
			     virDomainHostdevDefPtr dev,
			     const char *vroot)
{
	virSecurityLabelDefPtr seclabel;
	seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);
	if (seclabel == NULL)
            return -1;

	if (seclabel->norelabel)
            return 0;

	switch (dev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
	    return SmackSetSecurityHostdevSubsysLabel(def,dev,vroot);

        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
	    return SmackSetSecurityHostdevCapsLabel(def,dev,vroot);

        default:
	    return 0;

	}
}


static int
SmackRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr,
		                 virDomainDefPtr def,
				 virDomainHostdevDefPtr dev,
				 const char *vroot)
{
    virSecurityLabelDefPtr seclabel;	

    seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	return -1;

    if (seclabel->norelabel)
	return 0;

    switch (dev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return SmackRestoreSecurityHostdevSubsysLabel(mgr, dev, vroot);

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return SmackRestoreSecurityHostdevCapsLabel(mgr, dev, vroot);

    default:
        return 0;
    }
}
	

static int
SmackSetSavedStateLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	                virDomainDefPtr def,
                        const char *savefile) 
{
	 virSecurityLabelDefPtr seclabel;

         seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
         if (seclabel == NULL)
             return -1;

         if (seclabel->norelabel)
             return 0;

         return SmackSetFileLabel(savefile, seclabel->imagelabel);
}


static int
SmackRestoreSavedStateLabel(virSecurityManagerPtr mgr,
		            virDomainDefPtr def,
			    const char *savefile)
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SMACK_NAME);
    if (seclabel == NULL)
        return -1;

    if (seclabel->norelabel)
        return 0;

    return SmackRestoreSecurityFileLabel(mgr, savefile);
}

static int
SmackSetImageFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	             virDomainDefPtr def,
                     int fd) 
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);

    if (seclabel == NULL)
	return -1;

    if (seclabel->imagelabel == NULL)
	return 0;

    return SmackFSetFileLabel(fd,seclabel->imagelabel);
      
}


static int
SmackSetTapFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
	           virDomainDefPtr def,
                   int fd) 
{
    struct stat buf;
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME);
    if (seclabel == NULL)
	    return -1;

    if (seclabel->label == NULL)
	    return 0;
    

    if (fstat(fd, &buf) < 0) {
        virReportSystemError(errno, _("cannot stat tap fd %d"), fd);
	    return -1;
    }
   
    if ((buf.st_mode & S_IFMT) != S_IFCHR) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("tap fd %d is not character device"), fd);
	    return -1;
    }
       
    return SmackFSetFileLabel(fd,seclabel->label);
      
}


static char *
SmackGetMountOptions(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
		     virDomainDefPtr def)
{
	char *opts = NULL;
	virSecurityLabelDefPtr seclabel;
	
	if ((seclabel = virDomainDefGetSecurityLabelDef(def,SECURITY_SMACK_NAME))) {
              if (!seclabel->imagelabel)
		 seclabel->imagelabel = get_label_name(def); 

	      if (seclabel->imagelabel &&
                  virAsprintf(&opts,
			      ",smack_label=\"%s\"",
			      (const char*) seclabel->imagelabel) < 0) 
		  return NULL;
     }

        if (!opts && VIR_STRDUP(opts,"") < 0)
		return NULL;

	return opts;

}

static const char *
SmackGetBaseLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                  int virtType ATTRIBUTE_UNUSED)
{
   return NULL;
}


virSecurityDriver virSmackSecurityDriver = {
    .privateDataLen                   = 0,
    .name                             = SECURITY_SMACK_NAME,
    .probe                            = SmackSecurityDriverProbe,
    .open                             = SmackSecurityDriverOpen,
    .close                            = SmackSecurityDriverClose,

    .getModel                         = SmackSecurityDriverGetModel,
    .getDOI                           = SmackSecurityDriverGetDOI,

    .domainSecurityVerify             = SmackSecurityVerify,
	
    .domainSetSecurityImageLabel      = SmackSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel  = SmackRestoreSecurityImageLabel,

    .domainSetSecurityDaemonSocketLabel = SmackSetSecurityDaemonSocketLabel,

    .domainSetSecuritySocketLabel       = SmackSetSecuritySocketLabel,
    .domainClearSecuritySocketLabel     = SmackClearSecuritySocketLabel,

    .domainGenSecurityLabel             = SmackGenSecurityLabel,
    .domainReserveSecurityLabel         = SmackReserveSecurityLabel,
    .domainReleaseSecurityLabel         = SmackReleaseSecurityLabel,

    .domainGetSecurityProcessLabel      = SmackGetSecurityProcessLabel,
    .domainSetSecurityProcessLabel      = SmackSetSecurityProcessLabel,
    .domainSetSecurityChildProcessLabel = SmackSetSecurityChildProcessLabel,

    .domainSetSecurityAllLabel          = SmackSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel      = SmackRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel      = SmackSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = SmackRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel           = SmackSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = SmackRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = SmackSetImageFDLabel,
    .domainSetSecurityTapFDLabel        = SmackSetTapFDLabel,

    .domainGetSecurityMountOptions      = SmackGetMountOptions,

    .getBaseLabel                       = SmackGetBaseLabel,

};
