#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mount.h>

#ifdef __linux__
   #include <mntent.h>
   #include <sys/vfs.h>
#endif

#include "statfs.h"


int getstatfspath()
   {
   /* For OpenBSD */
   #ifdef __OpenBSD__
     int mntsize=0;
     int i=0;
     struct statfs *fs;
     mntsize = getmntinfo(&fs, MNT_NOWAIT);
     if(mntsize == 0)
      {
      return(-1);
      }

     for(i=0;i<mntsize;i++)
      getstatfs(fs[i].f_mntonname);

    /* For Linux */
   #elif defined( __linux__ )
     struct  mntent *m;
     FILE *f;
     f = setmntent("/etc/mtab", "r");
     while ((m = getmntent(f)))
	getstatfs(m->mnt_dir);
     endmntent(f);
   #endif

   return(0);
   }



int getstatfs(char *path)
{
    struct statfs fs;
    int percentbfree=0;
    int percentnfree=0;
 
    if(statfs(path, &fs) != 0)
	return(-1);

    if((fs.f_bfree == 0)||(fs.f_ffree == 0))
	    return(-1);
    percentbfree = (int)(100*fs.f_bfree)/fs.f_blocks;     
    percentnfree = (int)(100*fs.f_ffree)/fs.f_files;     
    printf("file system for %s has %d free blocks out of a total of %d - %d. Total of %d%% FREE \n",path,fs.f_ffree,fs.f_blocks,percentbfree,percentnfree);
   return(0);
}
