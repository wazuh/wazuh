/*
 * Copyright 1998-2002 by Albert Cahalan; all rights resered.
 * This file may be used subject to the terms and conditions of the
 * GNU Library General Public License Version 2, or any later version
 * at your option, as published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Library General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "version.h"
#include "devname.h"

// This is the buffer size for a tty name. Any path is legal,
// which makes PAGE_SIZE appropriate (see kernel source), but
// that is only 99% portable and utmp only holds 32 anyway.
// We need at least 20 for guess_name().
#define TTY_NAME_SIZE 128

/* Who uses what:
 *
 * tty_to_dev   w (there is a fancy version in ps)
 * dev_to_tty   top, ps
 */

#if 0
#include <sys/sysmacros.h>
#define MAJOR_OF(d) ((unsigned)major(d))
#define MINOR_OF(d) ((unsigned)minor(d))
#else
#define MAJOR_OF(d) ( ((unsigned)(d)>>8u) & 0xfffu )
#define MINOR_OF(d) ( ((unsigned)(d)&0xffu) | (((unsigned)(d)&0xfff00000u)>>12u) )
#undef major
#undef minor
#define major <-- do not use -->
#define minor <-- do not use -->
#endif

typedef struct tty_map_node {
  struct tty_map_node *next;
  unsigned short devfs_type;  // bool
  unsigned short major_number;
  unsigned minor_first;
  unsigned minor_last;
  char name[16];
} tty_map_node;

static tty_map_node *tty_map = NULL;

/* Load /proc/tty/drivers for device name mapping use. */
static void load_drivers(void){
  char buf[10000];
  char *p;
  int fd;
  int bytes;
  fd = open("/proc/tty/drivers",O_RDONLY);
  if(fd == -1) goto fail;
  bytes = read(fd, buf, sizeof(buf) - 1);
  if(bytes == -1) goto fail;
  buf[bytes] = '\0';
  p = buf;
  while(( p = strstr(p, " /dev/") )){  // " /dev/" is the second column
    tty_map_node *tmn;
    unsigned int len;
    char *end;
    p += 6;
    end = strchr(p, ' ');
    if(!end) continue;
    len = end - p;
    tmn = calloc(1, sizeof(tty_map_node));
    tmn->next = tty_map;
    tty_map = tmn;
    /* if we have a devfs type name such as /dev/tts/%d then strip the %d but
       keep a flag. */
    if(len >= 3 && !strncmp(end - 2, "%d", 2)){
      len -= 2;
      tmn->devfs_type = 1;
    }
    if(len >= sizeof tmn->name)
      len = sizeof tmn->name - 1; // mangle it to avoid overflow
    memcpy(tmn->name, p, len);
    p = end; /* set p to point past the %d as well if there is one */
    while(*p == ' ') p++;
    tmn->major_number = atoi(p);
    p += strspn(p, "0123456789");
    while(*p == ' ') p++;
    switch(sscanf(p, "%u-%u", &tmn->minor_first, &tmn->minor_last)){
    default:
      /* Can't finish parsing this line so we remove it from the list */
      tty_map = tty_map->next;
      free(tmn);
      break;
    case 1:
      tmn->minor_last = tmn->minor_first;
      break;
    case 2:
      break;
    }
  }
fail:
  if(fd != -1) close(fd);
  if(!tty_map) tty_map = (tty_map_node *)-1;
}

/* Try to guess the device name from /proc/tty/drivers info. */
static int driver_name(char *restrict const buf, unsigned maj, unsigned min){
  struct stat sbuf;
  tty_map_node *tmn;
  if(!tty_map) load_drivers();
  if(tty_map == (tty_map_node *)-1) return 0;
  tmn = tty_map;
  for(;;){
    if(!tmn) return 0;
    if(tmn->major_number == maj && tmn->minor_first <= min && tmn->minor_last >= min) break;
    tmn = tmn->next;
  }
  sprintf(buf, "/dev/%s%d", tmn->name, min);  /* like "/dev/ttyZZ255" */
  if(stat(buf, &sbuf) < 0){
    if(tmn->devfs_type) return 0;
    sprintf(buf, "/dev/%s", tmn->name);  /* like "/dev/ttyZZ255" */
    if(stat(buf, &sbuf) < 0) return 0;
  }
  if(min != MINOR_OF(sbuf.st_rdev)) return 0;
  if(maj != MAJOR_OF(sbuf.st_rdev)) return 0;
  return 1;
}

// major 204 is a mess -- "Low-density serial ports"
static const char low_density_names[][6] = {
"LU0",  "LU1",  "LU2",  "LU3",
"FB0",
"SA0",  "SA1",  "SA2",
"SC0",  "SC1",  "SC2",  "SC3",
"FW0",  "FW1",  "FW2",  "FW3",
"AM0",  "AM1",  "AM2",  "AM3",  "AM4",  "AM5",  "AM6",  "AM7",
"AM8",  "AM9",  "AM10", "AM11", "AM12", "AM13", "AM14", "AM15",
"DB0",  "DB1",  "DB2",  "DB3",  "DB4",  "DB5",  "DB6",  "DB7",
"SG0",
"SMX0",  "SMX1",  "SMX2",
"MM0",  "MM1",
"CPM0", "CPM1", "CPM2", "CPM3", /* "CPM4", "CPM5", */  // bad allocation?
"IOC0",  "IOC1",  "IOC2",  "IOC3",  "IOC4",  "IOC5",  "IOC6",  "IOC7",
"IOC8",  "IOC9",  "IOC10", "IOC11", "IOC12", "IOC13", "IOC14", "IOC15",
"IOC16", "IOC17", "IOC18", "IOC19", "IOC20", "IOC21", "IOC22", "IOC23",
"IOC24", "IOC25", "IOC26", "IOC27", "IOC28", "IOC29", "IOC30", "IOC31",
"VR0", "VR1",
"IOC84",  "IOC85",  "IOC86",  "IOC87",  "IOC88",  "IOC89",  "IOC90",  "IOC91",
"IOC92",  "IOC93",  "IOC94", "IOC95", "IOC96", "IOC97", "IOC98", "IOC99",
"IOC100", "IOC101", "IOC102", "IOC103", "IOC104", "IOC105", "IOC106", "IOC107",
"IOC108", "IOC109", "IOC110", "IOC111", "IOC112", "IOC113", "IOC114", "IOC115",
"SIOC0",  "SIOC1",  "SIOC2",  "SIOC3",  "SIOC4",  "SIOC5",  "SIOC6",  "SIOC7",
"SIOC8",  "SIOC9",  "SIOC10", "SIOC11", "SIOC12", "SIOC13", "SIOC14", "SIOC15",
"SIOC16", "SIOC17", "SIOC18", "SIOC19", "SIOC20", "SIOC21", "SIOC22", "SIOC23",
"SIOC24", "SIOC25", "SIOC26", "SIOC27", "SIOC28", "SIOC29", "SIOC30", "SIOC31",
"PSC0", "PSC1", "PSC2", "PSC3", "PSC4", "PSC5",
"AT0",  "AT1",  "AT2",  "AT3",  "AT4",  "AT5",  "AT6",  "AT7",
"AT8",  "AT9",  "AT10", "AT11", "AT12", "AT13", "AT14", "AT15",
"NX0",  "NX1",  "NX2",  "NX3",  "NX4",  "NX5",  "NX6",  "NX7",
"NX8",  "NX9",  "NX10", "NX11", "NX12", "NX13", "NX14", "NX15",
"J0",   // minor is 186
"UL0","UL1","UL2","UL3",
"xvc0", // FAIL -- "/dev/xvc0" lacks "tty" prefix
"PZ0","PZ1","PZ2","PZ3",
"TX0","TX1","TX2","TX3","TX4","TX5","TX6","TX7",
"SC0","SC1","SC2","SC3",
"MAX0","MAX1","MAX2","MAX3",
};

#if 0
// test code
#include <stdio.h>
#define AS(x) (sizeof(x)/sizeof((x)[0]))
int main(int argc, char *argv[]){
  int i = 0;
  while(i<AS(low_density_names)){
    printf("%3d = /dev/tty%.*s\n",i,sizeof low_density_names[i],low_density_names[i]);
    i++;
  }
  return 0;
}
#endif

/* Try to guess the device name (useful until /proc/PID/tty is added) */
static int guess_name(char *restrict const buf, unsigned maj, unsigned min){
  struct stat sbuf;
  int t0, t1;
  unsigned tmpmin = min;

  switch(maj){
  case   3:      /* /dev/[pt]ty[p-za-o][0-9a-z] is 936 */
    if(tmpmin > 255) return 0;   // should never happen; array index protection
    t0 = "pqrstuvwxyzabcde"[tmpmin>>4];
    t1 = "0123456789abcdef"[tmpmin&0x0f];
    sprintf(buf, "/dev/tty%c%c", t0, t1);
    break;
  case   4:
    if(min<64){
      sprintf(buf, "/dev/tty%d", min);
      break;
    }
    sprintf(buf, "/dev/ttyS%d", min-64);
    break;
  case  11:  sprintf(buf, "/dev/ttyB%d",  min); break;
  case  17:  sprintf(buf, "/dev/ttyH%d",  min); break;
  case  19:  sprintf(buf, "/dev/ttyC%d",  min); break;
  case  22:  sprintf(buf, "/dev/ttyD%d",  min); break; /* devices.txt */
  case  23:  sprintf(buf, "/dev/ttyD%d",  min); break; /* driver code */
  case  24:  sprintf(buf, "/dev/ttyE%d",  min); break;
  case  32:  sprintf(buf, "/dev/ttyX%d",  min); break;
  case  43:  sprintf(buf, "/dev/ttyI%d",  min); break;
  case  46:  sprintf(buf, "/dev/ttyR%d",  min); break;
  case  48:  sprintf(buf, "/dev/ttyL%d",  min); break;
  case  57:  sprintf(buf, "/dev/ttyP%d",  min); break;
  case  71:  sprintf(buf, "/dev/ttyF%d",  min); break;
  case  75:  sprintf(buf, "/dev/ttyW%d",  min); break;
  case  78:  sprintf(buf, "/dev/ttyM%d",  min); break; /* conflict */
  case 105:  sprintf(buf, "/dev/ttyV%d",  min); break;
  case 112:  sprintf(buf, "/dev/ttyM%d",  min); break; /* conflict */
  /* 136 ... 143 are /dev/pts/0, /dev/pts/1, /dev/pts/2 ... */
  case 136 ... 143:  sprintf(buf, "/dev/pts/%d",  min+(maj-136)*256); break;
  case 148:  sprintf(buf, "/dev/ttyT%d",  min); break;
  case 154:  sprintf(buf, "/dev/ttySR%d", min); break;
  case 156:  sprintf(buf, "/dev/ttySR%d", min+256); break;
  case 164:  sprintf(buf, "/dev/ttyCH%d",  min); break;
  case 166:  sprintf(buf, "/dev/ttyACM%d", min); break; /* bummer, 9-char */
  case 172:  sprintf(buf, "/dev/ttyMX%d",  min); break;
  case 174:  sprintf(buf, "/dev/ttySI%d",  min); break;
  case 188:  sprintf(buf, "/dev/ttyUSB%d", min); break; /* bummer, 9-char */
  case 204:
    if(min >= sizeof low_density_names / sizeof low_density_names[0]) return 0;
    memcpy(buf,"/dev/tty",8);
    memcpy(buf+8, low_density_names[min], sizeof low_density_names[0]);
    buf[8 + sizeof low_density_names[0]] = '\0';
//    snprintf(buf, 9 + sizeof low_density_names[0], "/dev/tty%.*s", sizeof low_density_names[0], low_density_names[min]);
    break;
  case 208:  sprintf(buf, "/dev/ttyU%d",  min); break;
  case 216:  sprintf(buf, "/dev/ttyUB%d",  min); break; // "/dev/rfcomm%d" now?
  case 224:  sprintf(buf, "/dev/ttyY%d",  min); break;
  case 227:  sprintf(buf, "/dev/3270/tty%d", min); break; /* bummer, HUGE */
  case 229:  sprintf(buf, "/dev/iseries/vtty%d",  min); break; /* bummer, HUGE */
  case 256:  sprintf(buf, "/dev/ttyEQ%d",  min); break;
  default: return 0;
  }
  if(stat(buf, &sbuf) < 0) return 0;
  if(min != MINOR_OF(sbuf.st_rdev)) return 0;
  if(maj != MAJOR_OF(sbuf.st_rdev)) return 0;
  return 1;
}

/* Linux 2.2 can give us filenames that might be correct.
 * Useful names could be in /proc/PID/fd/2 (stderr, seldom redirected)
 * and in /proc/PID/fd/255 (used by bash to remember the tty).
 */
static int link_name(char *restrict const buf, unsigned maj, unsigned min, int pid, const char *restrict name){
  struct stat sbuf;
  char path[32];
  int count;
  sprintf(path, "/proc/%d/%s", pid, name);  /* often permission denied */
  count = readlink(path,buf,TTY_NAME_SIZE-1);
  if(count == -1) return 0;
  buf[count] = '\0';
  if(stat(buf, &sbuf) < 0) return 0;
  if(min != MINOR_OF(sbuf.st_rdev)) return 0;
  if(maj != MAJOR_OF(sbuf.st_rdev)) return 0;
  return 1;
}

/* number --> name */
unsigned dev_to_tty(char *restrict ret, unsigned chop, dev_t dev_t_dev, int pid, unsigned int flags) {
  static char buf[TTY_NAME_SIZE];
  char *restrict tmp = buf;
  unsigned dev = dev_t_dev;
  unsigned i = 0;
  int c;
  if(dev == 0u) goto no_tty;
  if(linux_version_code > LINUX_VERSION(2, 7, 0)){  // not likely to make 2.6.xx
    if(link_name(tmp, MAJOR_OF(dev), MINOR_OF(dev), pid, "tty"   )) goto abbrev;
  }
  if(driver_name(tmp, MAJOR_OF(dev), MINOR_OF(dev)               )) goto abbrev;
  if(  link_name(tmp, MAJOR_OF(dev), MINOR_OF(dev), pid, "fd/2"  )) goto abbrev;
  if( guess_name(tmp, MAJOR_OF(dev), MINOR_OF(dev)               )) goto abbrev;
  if(  link_name(tmp, MAJOR_OF(dev), MINOR_OF(dev), pid, "fd/255")) goto abbrev;
  // fall through if unable to find a device file
no_tty:
  strcpy(ret, "?");
  return 1;
abbrev:
  if((flags&ABBREV_DEV) && !strncmp(tmp,"/dev/",5) && tmp[5]) tmp += 5;
  if((flags&ABBREV_TTY) && !strncmp(tmp,"tty",  3) && tmp[3]) tmp += 3;
  if((flags&ABBREV_PTS) && !strncmp(tmp,"pts/", 4) && tmp[4]) tmp += 4;
  /* gotta check before we chop or we may chop someone else's memory */
  if(chop + (unsigned long)(tmp-buf) <= sizeof buf)
    tmp[chop] = '\0';
  /* replace non-ASCII characters with '?' and return the number of chars */
  for(;;){
    c = *tmp;
    tmp++;
    if(!c) break;
    i++;
    if(c<=' ') c = '?';
    if(c>126)  c = '?';
    *ret = c;
    ret++;
  }
  *ret = '\0';
  return i;
}

/* name --> number */
int tty_to_dev(const char *restrict const name) {
  struct stat sbuf;
  static char buf[32];
  if(name[0]=='/' && stat(name, &sbuf) >= 0) return sbuf.st_rdev;
  snprintf(buf,32,"/dev/%s",name);
  if(stat(buf, &sbuf) >= 0) return sbuf.st_rdev;
  snprintf(buf,32,"/dev/tty%s",name);
  if(stat(buf, &sbuf) >= 0) return sbuf.st_rdev;
  snprintf(buf,32,"/dev/pts/%s",name);
  if(stat(buf, &sbuf) >= 0) return sbuf.st_rdev;
  return -1;
}
