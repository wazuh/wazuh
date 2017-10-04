#if 0
#include "procps.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "procps.h"

struct smap_entry {
	unsigned KLONG start;
	unsigned KLONG beyond;
	long long offset;
	char flags[8];
	unsigned dev_major;
	unsigned dev_minor;
	unsigned long long inode;

	unsigned long rss;
	unsigned long pss;
	unsigned long sclean;
	unsigned long sdirty;
	unsigned long pclean;
	unsigned long pdirty;
	unsigned long ref;
	unsigned long swap;
};


////////////////////////////////////////////////////////////////////////////////
// This code will surely make normal programmers cry. I need speed though,
// and /proc/*/smaps should make anybody cry. (WTF kind of brain damage...?)

struct smap_summary {
	unsigned long size;
	unsigned long rss;
	unsigned long pss;
	unsigned long sclean;
	unsigned long sdirty;
	unsigned long pclean;
	unsigned long pdirty;
	unsigned long ref;
	unsigned long swap;
};

struct ssjt {
	char str[16];
	int len;
	int offset;
};

#define JTE(o,x) {#x,sizeof(#x)-1,o}

void get_smap_sums(struct smap_summary *restrict ss, const char *restrict const filename){
	static struct ssjt table[] = {
		JTE(-1,default),
		JTE( 1,Rss),
		JTE(-1,default),
		JTE( 2,Pss),
		JTE( 8,Swap),
		JTE( 5,Private_Clean),
		JTE( 6,Private_Dirty),
		JTE(-1,default),
		JTE( 7,Referenced),
		JTE(-1,default),
		JTE( 0,Size),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default), // KernelPageSize would go here
		JTE(-1,default),
		JTE(-1,default),
		JTE( 4,Shared_Dirty),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE( 3,Shared_Clean),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
		JTE(-1,default),
	};
	char buf[20480];
	int p1 = 0;
	int p2 = 0;
	memset(ss,0,sizeof *ss);
	int fd = open(filename,O_RDONLY);
	if(fd==-1)
		return;
	for(;;){
		char *nlp = memchr(buf+p1,'\n',p2-p1);
		if(!nlp){
			if(p1){
				// the memmove should never do anything, because the
				// kernel seems to give us the greatest number of
				// complete lines of text that fit in a single page
				// (and thus p2-p1 is zero)
				memmove(buf,buf+p1,p2-p1);
				p2 -= p1;
				p1 = 0;
			}
			ssize_t rb = read(fd,buf+p1,sizeof buf - p1);
			if(rb < 1)
				break;
			p2 += rb;
			nlp = memchr(buf+p1,'\n',p2-p1);
			if(!nlp)
				break;
		}
		char *s = buf+p1;
		int len = nlp-s;
		p1 += len+1;
		if(len<27)
			continue;
//printf("j      <%13.13s>\n",s);
		if(s[0]<'A' || s[0]>'Z')
			continue;
		unsigned hash = ( (s[8]&15) + (s[1]&15) ) ^ (s[0]&3);
		hash &= 31;
//printf("x   %2d <%13.13s>\n",hash,s);
		if(s[table[hash].len] != ':')
			continue;
//printf("y   %2d <%13.13s>\n",hash,s);
		if(memcmp(table[hash].str,s,table[hash].len))
			continue;
//printf("z   %2d <%13.13s>\n",hash,s);
		s += table[hash].len;
		while(*++s==' ')
			;
		unsigned long ul = 0;
		for(;;){
			char c = *s++;
			if(c != ' '){
				ul *= 10;
				ul += c-'0';
				continue;
			}
			break;
		}
//		if(table[hash].offset == 2)
//			printf("Pss:%20lu kB\n",ul);
		unsigned long *ulp = &ss->size + table[hash].offset;
		*ulp += ul;
//		memcpy(ss+table[hash].offset*sizeof(unsigned long), &ul, sizeof(unsigned long));
	}
	close(fd);
}

int main(int argc, char *argv[]){
	struct smap_summary ss;
	get_smap_sums(&ss, argv[1]);
	printf("%9lu\n",ss.size);
	printf("%9lu\n",ss.rss);
	printf("%9lu\n",ss.pss);
	printf("%9lu\n",ss.sclean);
	printf("%9lu\n",ss.sdirty);
	printf("%9lu\n",ss.pclean);
	printf("%9lu\n",ss.pdirty);
	printf("%9lu\n",ss.ref);
	printf("%9lu\n",ss.swap);
	return 0;
}
#endif
