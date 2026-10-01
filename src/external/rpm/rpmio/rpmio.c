/** \ingroup rpmio
 * \file rpmio/rpmio.c
 */

#include "system.h"
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmsw.h>
#include <rpm/rpmurl.h>

#include "rpmio_internal.h"

#include "debug.h"

typedef struct FDSTACK_s * FDSTACK_t;

struct FDSTACK_s {
    FDIO_t		io;
    void *		fp;
    int			fdno;
    int			syserrno;	/* last system errno encountered */
    const char 		*errcookie;	/* pointer to custom error string */

    FDSTACK_t		prev;
};

/** \ingroup rpmio
 * Cumulative statistics for a descriptor.
 */
typedef	struct {
    struct rpmop_s	ops[FDSTAT_MAX];	/*!< Cumulative statistics. */
} * FDSTAT_t;

/** \ingroup rpmio
 * The FD_t File Handle data structure.
 */
struct _FD_s {
    int		nrefs;
    int		flags;
#define	RPMIO_DEBUG_IO		0x40000000
    int		magic;
#define	FDMAGIC			0x04463138
    FDSTACK_t	fps;
    int		urlType;	/* ufdio: */

    char	*descr;		/* file name (or other description) */
    FDSTAT_t	stats;		/* I/O statistics */

    rpmDigestBundle digests;
};

#define DBG(_f, _m, _x) \
    \
    if ((_rpmio_debug | ((_f) ? ((FD_t)(_f))->flags : 0)) & (_m)) fprintf _x \

#define DBGIO(_f, _x)   DBG((_f), RPMIO_DEBUG_IO, _x)

static FDSTACK_t fdGetFps(FD_t fd)
{
    return (fd != NULL) ? fd->fps : NULL;
}

static void fdSetFdno(FD_t fd, int fdno)
{
    if (fd) 
	fd->fps->fdno = fdno;
}

static void fdPush(FD_t fd, FDIO_t io, void * fp, int fdno)
{
    FDSTACK_t fps = (FDSTACK_t) xcalloc(1, sizeof(*fps));
    fps->io = io;
    fps->fp = fp;
    fps->fdno = fdno;
    fps->prev = fd->fps;

    fd->fps = fps;
    fdLink(fd);
}

static FDSTACK_t fdPop(FD_t fd)
{
    FDSTACK_t fps = fd->fps;
    fd->fps = fps->prev;
    free(fps);
    fps = fd->fps;
    fdFree(fd);
    return fps;
}

void fdSetBundle(FD_t fd, rpmDigestBundle bundle)
{
    if (fd)
	fd->digests = bundle;
}

rpmDigestBundle fdGetBundle(FD_t fd, int create)
{
    rpmDigestBundle bundle = NULL;
    if (fd) {
	if (fd->digests == NULL && create)
	    fd->digests = rpmDigestBundleNew();
	bundle = fd->digests;
    }
    return bundle;
}

/** \ingroup rpmio
 * \name RPMIO Vectors.
 */
typedef ssize_t (*fdio_read_function_t) (FDSTACK_t fps, void *buf, size_t nbytes);
typedef ssize_t (*fdio_write_function_t) (FDSTACK_t fps, const void *buf, size_t nbytes);
typedef int (*fdio_seek_function_t) (FDSTACK_t fps, off_t pos, int whence);
typedef int (*fdio_close_function_t) (FDSTACK_t fps);
typedef FD_t (*fdio_open_function_t) (const char * path, int flags, mode_t mode);
typedef FD_t (*fdio_fdopen_function_t) (FD_t fd, int fdno, const char * fmode);
typedef int (*fdio_fflush_function_t) (FDSTACK_t fps);
typedef off_t (*fdio_ftell_function_t) (FDSTACK_t fps);
typedef int (*fdio_ferror_function_t) (FDSTACK_t fps);
typedef const char * (*fdio_fstrerr_function_t)(FDSTACK_t fps);

struct FDIO_s {
  const char *			ioname;
  const char *			name;
  fdio_read_function_t		read;
  fdio_write_function_t		write;
  fdio_seek_function_t		seek;
  fdio_close_function_t		close;

  fdio_open_function_t		_open;
  fdio_fdopen_function_t	_fdopen;
  fdio_fflush_function_t	_fflush;
  fdio_ftell_function_t		_ftell;
  fdio_ferror_function_t	_ferror;
  fdio_fstrerr_function_t	_fstrerr;
};

/** \ingroup rpmio
 * Update digest(s) attached to fd.
 */
static void fdUpdateDigests(FD_t fd, const void * buf, size_t buflen);
static FD_t fdNew(int fdno, const char *descr);
/**
 */
int _rpmio_debug = 0;

/* =============================================================== */

static const char * fdbg(FD_t fd)
{
    static char buf[BUFSIZ];
    char *be = buf;

    buf[0] = '\0';
    if (fd == NULL)
	return buf;

    *be++ = '\t';
    for (FDSTACK_t fps = fd->fps; fps != NULL; fps = fps->prev) {
	FDIO_t iot = fps->io;
	if (fps != fd->fps)
	    *be++ = ' ';
	*be++ = '|';
	*be++ = ' ';
	/* plain fd io types dont have _fopen() method */
	if (iot->_fdopen == NULL) {
	    sprintf(be, "%s %d fp %p", iot->ioname, fps->fdno, fps->fp);
	} else {
	    sprintf(be, "%s %p fp %d", iot->ioname, fps->fp, fps->fdno);
	}
	be += strlen(be);
	*be = '\0';
    }
    return buf;
}

static void fdstat_enter(FD_t fd, fdOpX opx)
{
    if (fd->stats != NULL)
	(void) rpmswEnter(fdOp(fd, opx), (ssize_t) 0);
}

static void fdstat_exit(FD_t fd, fdOpX opx, ssize_t rc)
{
    if (rc == -1) {
	FDSTACK_t fps = fdGetFps(fd);
	fps->syserrno = errno;
    }
    if (fd->stats != NULL)
	(void) rpmswExit(fdOp(fd, opx), rc);
}

static void fdstat_print(FD_t fd, const char * msg, FILE * fp)
{
    static const int usec_scale = (1000*1000);
    int opx;

    if (fd == NULL || fd->stats == NULL) return;
    for (opx = 0; opx < 4; opx++) {
	rpmop op = &fd->stats->ops[opx];
	if (op->count <= 0) continue;
	switch (opx) {
	case FDSTAT_READ:
	    if (msg) fprintf(fp, "%s:", msg);
	    fprintf(fp, "%8d reads, %8ld total bytes in %d.%06d secs\n",
		op->count, (long)op->bytes,
		(int)(op->usecs/usec_scale), (int)(op->usecs%usec_scale));
	    break;
	case FDSTAT_WRITE:
	    if (msg) fprintf(fp, "%s:", msg);
	    fprintf(fp, "%8d writes, %8ld total bytes in %d.%06d secs\n",
		op->count, (long)op->bytes,
		(int)(op->usecs/usec_scale), (int)(op->usecs%usec_scale));
	    break;
	case FDSTAT_SEEK:
	    break;
	case FDSTAT_CLOSE:
	    break;
	}
    }
}

off_t fdSize(FD_t fd)
{
    struct stat sb;
    off_t rc = -1; 

    if (fd != NULL && fstat(Fileno(fd), &sb) == 0)
	rc = sb.st_size;
    return rc;
}

FD_t fdDup(int fdno)
{
    FD_t fd;
    int nfdno;

    if ((nfdno = dup(fdno)) < 0)
	return NULL;
    fd = fdNew(nfdno, NULL);
DBGIO(fd, (stderr, "==> fdDup(%d) fd %p %s\n", fdno, (fd ? fd : NULL), fdbg(fd)));
    return fd;
}

/* Regular fd doesn't have fflush() equivalent but its not an error either */
static int fdFlush(FDSTACK_t fps)
{
    return 0;
}

static int fdError(FDSTACK_t fps)
{
    return fps->syserrno;
}

static int zfdError(FDSTACK_t fps)
{
    return (fps->syserrno || fps->errcookie != NULL) ? -1 : 0;
}

static const char * fdStrerr(FDSTACK_t fps)
{
    return (fps->syserrno != 0) ? strerror(fps->syserrno) : "";
}

static const char * zfdStrerr(FDSTACK_t fps)
{
    return (fps->errcookie != NULL) ? fps->errcookie : "";
}

const char * Fdescr(FD_t fd)
{
    if (fd == NULL)
	return _("[none]");

    /* Lazy lookup if description is not set (eg dupped fd) */
    if (fd->descr == NULL) {
	int fdno = fd->fps->fdno;
#if defined(__linux__)
	/* Grab the path from /proc if we can */
	char *procpath = NULL;
	char buf[PATH_MAX];
	ssize_t llen;

	rasprintf(&procpath, "/proc/self/fd/%d", fdno);
	llen = readlink(procpath, buf, sizeof(buf)-1);
	free(procpath);

	if (llen >= 1) {
	    buf[llen] = '\0';
	    /* Real paths in /proc are always absolute */
	    if (buf[0] == '/')
		fd->descr = xstrdup(buf);
	    else
		fd->descr = rstrscat(NULL, "[", buf, "]", NULL);
	}
#endif
	/* Still no description, base it on fdno which is always there */
	if (fd->descr == NULL)
	    rasprintf(&(fd->descr), "[fd %d]", fdno);
    }
    return fd->descr;
}

FD_t fdLink(FD_t fd)
{
    if (fd)
	fd->nrefs++;
    return fd;
}

FD_t fdFree( FD_t fd)
{
    if (fd) {
	if (--fd->nrefs > 0)
	    return fd;
	fd->stats = _free(fd->stats);
	if (fd->digests) {
	    fd->digests = rpmDigestBundleFree(fd->digests);
	}
	free(fd->fps);
	free(fd->descr);
	free(fd);
    }
    return NULL;
}

static FD_t fdNew(int fdno, const char *descr)
{
    FD_t fd = (FD_t)xcalloc(1, sizeof(*fd));
    fd->nrefs = 0;
    fd->flags = 0;
    fd->magic = FDMAGIC;
    fd->urlType = URL_IS_UNKNOWN;
    fd->stats = (FDSTAT_t)xcalloc(1, sizeof(*fd->stats));
    fd->digests = NULL;
    fd->descr = descr ? xstrdup(descr) : NULL;

    fdPush(fd, fdio, NULL, fdno);
    return fd;
}

static ssize_t fdRead(FDSTACK_t fps, void * buf, size_t count)
{
    return read(fps->fdno, buf, count);
}

static ssize_t fdWrite(FDSTACK_t fps, const void * buf, size_t count)
{
    if (count == 0)
	return 0;

    return write(fps->fdno, buf, count);
}

static int fdSeek(FDSTACK_t fps, off_t pos, int whence)
{
    return (lseek(fps->fdno, pos, whence) == -1) ? -1 : 0;
}

static int fdClose(FDSTACK_t fps)
{
    int fdno = fps->fdno;
    int rc;

    fps->fdno = -1;

    rc = ((fdno >= 0) ? close(fdno) : -2);

    return rc;
}

static FD_t fdOpen(const char *path, int flags, mode_t mode)
{
    FD_t fd;
    int fdno;

    fdno = open(path, flags, mode);
    if (fdno < 0) return NULL;
    if (fcntl(fdno, F_SETFD, FD_CLOEXEC)) {
	(void) close(fdno);
	return NULL;
    }
    fd = fdNew(fdno, path);
    fd->flags = flags;
    return fd;
}

static off_t fdTell(FDSTACK_t fps)
{
    return lseek(fps->fdno, 0, SEEK_CUR);
}

static const struct FDIO_s fdio_s = {
  "fdio", NULL,
  fdRead, fdWrite, fdSeek, fdClose,
  fdOpen, NULL, fdFlush, fdTell, fdError, fdStrerr,
};
const FDIO_t fdio = &fdio_s ;

off_t ufdCopy(FD_t sfd, FD_t tfd)
{
    char buf[BUFSIZ];
    ssize_t rdbytes, wrbytes;
    off_t total = 0;

    while (1) {
	rdbytes = Fread(buf, sizeof(buf[0]), sizeof(buf), sfd);

	if (rdbytes > 0) {
	    wrbytes = Fwrite(buf, sizeof(buf[0]), rdbytes, tfd);
	    if (wrbytes != rdbytes) {
		total = -1;
		break;
	    }
	    total += wrbytes;
	} else {
	    if (rdbytes < 0)
		total = -1;
	    break;
	}
    }

    return total;
}

/*
 * Deal with remote url's by fetching them with a helper application
 * and treat as local file afterwards.
 * TODO:
 * - better error checking + reporting 
 * - curl & friends don't know about hkp://, transform to http?
 */

static FD_t urlOpen(const char * url, int flags, mode_t mode)
{
    FD_t fd;
    char *dest = NULL;
    int rc = 1; /* assume failure */

    fd = rpmMkTempFile(NULL, &dest);
    if (fd == NULL) {
	return NULL;
    }
    Fclose(fd);

    rc = urlGetFile(url, dest);
    if (rc == 0) {
	fd = fdOpen(dest, flags, mode);
	unlink(dest);
    } else {
	fd = NULL;
	errno = ENOENT;
    }
    dest = _free(dest);

    return fd;

}
static FD_t ufdOpen(const char * url, int flags, mode_t mode)
{
    FD_t fd = NULL;
    const char * path;
    urltype urlType = urlPath(url, &path);

if (_rpmio_debug)
fprintf(stderr, "*** ufdOpen(%s,0x%x,0%o)\n", url, (unsigned)flags, (unsigned)mode);

    switch (urlType) {
    case URL_IS_FTP:
    case URL_IS_HTTPS:
    case URL_IS_HTTP:
    case URL_IS_HKP:
	fd = urlOpen(url, flags, mode);
	/* we're dealing with local file when urlOpen() returns */
	urlType = URL_IS_UNKNOWN;
	break;
    case URL_IS_DASH:
	if ((flags & O_ACCMODE) == O_RDWR) {
	    fd = NULL;
	} else {
	    fd = fdDup((flags & O_ACCMODE) == O_WRONLY ?
			STDOUT_FILENO : STDIN_FILENO);
	}
	break;
    case URL_IS_PATH:
    case URL_IS_UNKNOWN:
    default:
	fd = fdOpen(path, flags, mode);
	break;
    }

    if (fd != NULL) {
	fd->fps->io = ufdio;
	fd->urlType = urlType;
    }
    return fd;
}

#if !ENABLE_OPENMP
#define omp_in_parallel() 0
#endif

/* Parse thread enablement string. T or T0 means autodetection */
static int parsethreadn(const char *s, char **end)
{
    int threads = strtol(s, end, 10);
    if (threads == 0) {
	/* Disable autodetection inside OpenMP parallel regions */
	if (!omp_in_parallel())
	    threads = rpmExpandNumeric("%{getncpus:thread}");
    }

    return threads;
}

static const struct FDIO_s ufdio_s = {
  "ufdio", NULL,
  fdRead, fdWrite, fdSeek, fdClose,
  ufdOpen, NULL, fdFlush, fdTell, fdError, fdStrerr
};
const FDIO_t ufdio = &ufdio_s ;

/* =============================================================== */
/* Support for GZIP library.  */
#include <zlib.h>
static gzFile gzdFp(FDSTACK_t fps)
{
    return (gzFile)fps->fp;
}

static FD_t gzdFdopen(FD_t fd, int fdno, const char *fmode)
{
    gzFile gzfile = gzdopen(fdno, fmode);

    if (gzfile == NULL)
	return NULL;

    fdSetFdno(fd, -1);		/* XXX skip the fdio close */
    fdPush(fd, gzdio, gzfile, fdno);		/* Push gzdio onto stack */
    return fd;
}

static int gzdFlush(FDSTACK_t fps)
{
    gzFile gzfile = gzdFp(fps);
    if (gzfile == NULL) return -2;
    return gzflush(gzfile, Z_SYNC_FLUSH);	/* XXX W2DO? */
}

static void gzdSetError(FDSTACK_t fps)
{
    gzFile gzfile = gzdFp(fps);
    int zerror = 0;
    fps->errcookie = gzerror(gzfile, &zerror);
    if (zerror == Z_ERRNO) {
	fps->syserrno = errno;
	fps->errcookie = strerror(fps->syserrno);
    }
}

static ssize_t gzdRead(FDSTACK_t fps, void * buf, size_t count)
{
    gzFile gzfile = gzdFp(fps);
    ssize_t rc;

    if (gzfile == NULL) return -2;	/* XXX can't happen */

    rc = gzread(gzfile, buf, count);
    if (rc < 0)
	gzdSetError(fps);
    return rc;
}

static ssize_t gzdWrite(FDSTACK_t fps, const void * buf, size_t count)
{
    gzFile gzfile;
    ssize_t rc;

    gzfile = gzdFp(fps);
    if (gzfile == NULL) return -2;	/* XXX can't happen */

    rc = gzwrite(gzfile, (void *)buf, count);
    if (rc < 0)
	gzdSetError(fps);
    return rc;
}

static int gzdSeek(FDSTACK_t fps, off_t pos, int whence)
{
    off_t p = pos;
    int rc;
    gzFile gzfile = gzdFp(fps);

    if (gzfile == NULL) return -2;	/* XXX can't happen */

    rc = gzseek(gzfile, p, whence);
    if (rc < 0)
	gzdSetError(fps);
    return rc;
}

static int gzdClose(FDSTACK_t fps)
{
    gzFile gzfile = gzdFp(fps);
    int rc;

    if (gzfile == NULL) return -2;	/* XXX can't happen */

    rc = gzclose(gzfile);

    return (rc != 0) ? -1 : 0;
}

static off_t gzdTell(FDSTACK_t fps)
{
    off_t pos = -1;
    gzFile gzfile = gzdFp(fps);

    if (gzfile != NULL) {
#ifdef HAVE_GZSEEK
	pos = gztell(gzfile);
	if (pos < 0)
	    gzdSetError(fps);
#else
	pos = -2;
#endif    
    }
    return pos;
}
static const struct FDIO_s gzdio_s = {
  "gzdio", "gzip",
  gzdRead, gzdWrite, gzdSeek, gzdClose,
  NULL, gzdFdopen, gzdFlush, gzdTell, zfdError, zfdStrerr
};
const FDIO_t gzdio = &gzdio_s ;

/* =============================================================== */
/* Support for BZIP2 library.  */
#ifdef HAVE_BZLIB_H

#include <bzlib.h>

static BZFILE *bzdFp(FDSTACK_t fps)
{
    return (BZFILE *)fps->fp;
}

static FD_t bzdFdopen(FD_t fd, int fdno, const char * fmode)
{
    BZFILE *bzfile = BZ2_bzdopen(fdno, fmode);

    if (bzfile == NULL)
	return NULL;

    fdSetFdno(fd, -1);		/* XXX skip the fdio close */
    fdPush(fd, bzdio, bzfile, fdno);		/* Push bzdio onto stack */
    return fd;
}

static int bzdFlush(FDSTACK_t fps)
{
    return BZ2_bzflush(bzdFp(fps));
}

static ssize_t bzdRead(FDSTACK_t fps, void * buf, size_t count)
{
    BZFILE *bzfile = bzdFp(fps);
    ssize_t rc = 0;

    if (bzfile)
	rc = BZ2_bzread(bzfile, buf, count);
    if (rc == -1) {
	int zerror = 0;
	if (bzfile) {
	    fps->errcookie = BZ2_bzerror(bzfile, &zerror);
	}
    }
    return rc;
}

static ssize_t bzdWrite(FDSTACK_t fps, const void * buf, size_t count)
{
    BZFILE *bzfile = bzdFp(fps);
    ssize_t rc;

    rc = BZ2_bzwrite(bzfile, (void *)buf, count);
    if (rc == -1) {
	int zerror = 0;
	fps->errcookie = BZ2_bzerror(bzfile, &zerror);
    }
    return rc;
}

static int bzdClose(FDSTACK_t fps)
{
    BZFILE *bzfile = bzdFp(fps);

    if (bzfile == NULL) return -2;

    /* bzclose() doesn't return errors */
    BZ2_bzclose(bzfile);

    return 0;
}

static const struct FDIO_s bzdio_s = {
  "bzdio", "bzip2",
  bzdRead, bzdWrite, NULL, bzdClose,
  NULL, bzdFdopen, bzdFlush, NULL, zfdError, zfdStrerr
};
const FDIO_t bzdio = &bzdio_s ;

#endif	/* HAVE_BZLIB_H */

/* =============================================================== */
/* Support for LZMA library.  */

#ifdef HAVE_LZMA_H

#include <sys/types.h>
#include <inttypes.h>
#include <lzma.h>

#define kBufferSize (1 << 15)

typedef struct lzfile {
  /* IO buffer */
    uint8_t buf[kBufferSize];

    lzma_stream strm;

    FILE *file;

    int encoding;
    int eof;

} LZFILE;

static LZFILE *lzopen_internal(const char *mode, int fd, int xz)
{
    unsigned int level = LZMA_PRESET_DEFAULT;
    int encoding = 0;
    FILE *fp;
    LZFILE *lzfile;
    lzma_ret ret;
    lzma_stream init_strm = LZMA_STREAM_INIT;
    uint64_t mem_limit = rpmExpandNumeric("%{_xz_memlimit}");
    unsigned int threads = 0;

    for (; *mode; mode++) {
	if (*mode == 'w')
	    encoding = 1;
	else if (*mode == 'r')
	    encoding = 0;
	else if (*mode >= '0' && *mode <= '9')
	    level = *mode - '0';
	else if (*mode == 'T') {
	    char *end = NULL;
	    threads = parsethreadn(mode+1, &end);
	    mode = end-1;
	}
    }
    fp = fdopen(fd, encoding ? "w" : "r");
    if (!fp)
	return NULL;
    lzfile = (LZFILE *)calloc(1, sizeof(*lzfile));
    lzfile->file = fp;
    lzfile->encoding = encoding;
    lzfile->eof = 0;
    lzfile->strm = init_strm;
    if (encoding) {
	if (xz) {
	    if (!threads) {
		ret = lzma_easy_encoder(&lzfile->strm, level, LZMA_CHECK_SHA256);
	    } else {
		lzma_mt mt_options = {
		    .flags = 0,
		    .threads = threads,
		    .block_size = 0,
		    .timeout = 0,
		    .preset = level,
		    .filters = NULL,
		    .check = LZMA_CHECK_SHA256 };

		ret = lzma_stream_encoder_mt(&lzfile->strm, &mt_options);
	    }
	} else {
	    lzma_options_lzma options;
	    lzma_lzma_preset(&options, level);
	    ret = lzma_alone_encoder(&lzfile->strm, &options);
	}
    } else {   /* lzma_easy_decoder_memusage(level) is not ready yet, use hardcoded limit for now */
	ret = lzma_auto_decoder(&lzfile->strm, mem_limit ? mem_limit : 100<<20, 0);
    }
    if (ret != LZMA_OK) {
	switch (ret) {
	    case LZMA_MEM_ERROR:
		rpmlog(RPMLOG_ERR, "liblzma: Memory allocation failed");
		break;

	    case LZMA_DATA_ERROR:
		rpmlog(RPMLOG_ERR, "liblzma: File size limits exceeded");
		break;

	    default:
		rpmlog(RPMLOG_ERR, "liblzma: <Unknown error (%d), possibly a bug", ret);
		break;
	}
	fclose(fp);
	free(lzfile);
	return NULL;
    }
    return lzfile;
}

static int lzclose(LZFILE *lzfile)
{
    lzma_ret ret;
    size_t n;
    int rc;

    if (!lzfile)
	return -1;
    if (lzfile->encoding) {
	for (;;) {
	    lzfile->strm.avail_out = kBufferSize;
	    lzfile->strm.next_out = lzfile->buf;
	    ret = lzma_code(&lzfile->strm, LZMA_FINISH);
	    if (ret != LZMA_OK && ret != LZMA_STREAM_END)
		return -1;
	    n = kBufferSize - lzfile->strm.avail_out;
	    if (n && fwrite(lzfile->buf, 1, n, lzfile->file) != n)
		return -1;
	    if (ret == LZMA_STREAM_END)
		break;
	}
    }
    lzma_end(&lzfile->strm);
    rc = fclose(lzfile->file);
    free(lzfile);
    return rc;
}

static ssize_t lzread(LZFILE *lzfile, void *buf, size_t len)
{
    lzma_ret ret;
    int eof = 0;

    if (!lzfile || lzfile->encoding)
      return -1;
    if (lzfile->eof)
      return 0;
    lzfile->strm.next_out = (uint8_t *)buf;
    lzfile->strm.avail_out = len;
    for (;;) {
	if (!lzfile->strm.avail_in) {
	    lzfile->strm.next_in = lzfile->buf;
	    lzfile->strm.avail_in = fread(lzfile->buf, 1, kBufferSize, lzfile->file);
	    if (!lzfile->strm.avail_in)
		eof = 1;
	}
	ret = lzma_code(&lzfile->strm, LZMA_RUN);
	if (ret == LZMA_STREAM_END) {
	    lzfile->eof = 1;
	    return len - lzfile->strm.avail_out;
	}
	if (ret != LZMA_OK)
	    return -1;
	if (!lzfile->strm.avail_out)
	    return len;
	if (eof)
	    return -1;
      }
}

static ssize_t lzwrite(LZFILE *lzfile, void *buf, size_t len)
{
    lzma_ret ret;
    size_t n;
    if (!lzfile || !lzfile->encoding)
	return -1;
    if (!len)
	return 0;
    lzfile->strm.next_in = (uint8_t *)buf;
    lzfile->strm.avail_in = len;
    for (;;) {
	lzfile->strm.next_out = lzfile->buf;
	lzfile->strm.avail_out = kBufferSize;
	ret = lzma_code(&lzfile->strm, LZMA_RUN);
	if (ret != LZMA_OK)
	    return -1;
	n = kBufferSize - lzfile->strm.avail_out;
	if (n && fwrite(lzfile->buf, 1, n, lzfile->file) != n)
	    return -1;
	if (!lzfile->strm.avail_in)
	    return len;
    }
}

static FD_t xzdFdopen(FD_t fd, int fdno, const char * fmode)
{
    LZFILE *lzfile = lzopen_internal(fmode, fdno, 1);

    if (lzfile == NULL)
	return NULL;

    fdSetFdno(fd, -1);          /* XXX skip the fdio close */
    fdPush(fd, xzdio, lzfile, fdno);
    return fd;
}

static LZFILE *lzdFp(FDSTACK_t fps)
{
    return (LZFILE*)fps->fp;
}

static FD_t lzdFdopen(FD_t fd, int fdno, const char * fmode)
{
    LZFILE *lzfile = lzopen_internal(fmode, fdno, 0);

    if (lzfile == NULL)
	return NULL;

    fdSetFdno(fd, -1);          /* XXX skip the fdio close */
    fdPush(fd, lzdio, lzfile, fdno);
    return fd;
}

static int lzdFlush(FDSTACK_t fps)
{
    LZFILE *lzfile = lzdFp(fps);
    return fflush(lzfile->file);
}

static ssize_t lzdRead(FDSTACK_t fps, void * buf, size_t count)
{
    LZFILE *lzfile = lzdFp(fps);
    ssize_t rc = 0;

    if (lzfile)
	rc = lzread(lzfile, buf, count);
    if (rc == -1) {
	fps->errcookie = "Lzma: decoding error";
    }
    return rc;
}

static ssize_t lzdWrite(FDSTACK_t fps, const void * buf, size_t count)
{
    LZFILE *lzfile = lzdFp(fps);
    ssize_t rc = 0;

    rc = lzwrite(lzfile, (void *)buf, count);
    if (rc < 0) {
	fps->errcookie = "Lzma: encoding error";
    }
    return rc;
}

static int lzdClose(FDSTACK_t fps)
{
    LZFILE *lzfile = lzdFp(fps);
    int rc;

    if (lzfile == NULL) return -2;
    rc = lzclose(lzfile);

    return rc;
}

static struct FDIO_s xzdio_s = {
  "xzdio", "xz",
  lzdRead, lzdWrite, NULL, lzdClose,
  NULL, xzdFdopen, lzdFlush, NULL, zfdError, zfdStrerr
};
const FDIO_t xzdio = &xzdio_s;

static struct FDIO_s lzdio_s = {
  "lzdio", "lzma",
  lzdRead, lzdWrite, NULL, lzdClose,
  NULL, lzdFdopen, lzdFlush, NULL, zfdError, zfdStrerr
};
const FDIO_t lzdio = &lzdio_s;

#endif	/* HAVE_LZMA_H */

/* =============================================================== */
/* Support for ZSTD library.  */
#ifdef HAVE_ZSTD

#include <zstd.h>

typedef struct rpmzstd_s {
    int flags;			/*!< open flags. */
    int fdno;
    int level;			/*!< compression level */
    FILE * fp;
    union {
	ZSTD_DStream *d;
	ZSTD_CStream *c;
    } stream;
    size_t nb;
    void * b;
    ZSTD_inBuffer zib;          /*!< ZSTD_inBuffer */
    ZSTD_outBuffer zob;         /*!< ZSTD_outBuffer */
} * rpmzstd;

static rpmzstd rpmzstdNew(int fdno, const char *fmode)
{
    rpmzstd zstd = NULL;
    int flags = 0;
    int level = 3;
    const char * s = fmode;
    char stdio[32];
    char *t = stdio;
    char *te = t + sizeof(stdio) - 2;
    int c;
    int threads = 0;
    int windowlog = 27;
    int longdist = 0;

    switch ((c = *s++)) {
    case 'a':
	*t++ = (char)c;
	flags &= ~O_ACCMODE;
	flags |= O_WRONLY | O_CREAT | O_APPEND;
	break;
    case 'w':
	*t++ = (char)c;
	flags &= ~O_ACCMODE;
	flags |= O_WRONLY | O_CREAT | O_TRUNC;
	break;
    case 'r':
	*t++ = (char)c;
	flags &= ~O_ACCMODE;
	flags |= O_RDONLY;
	break;
    }

    while ((c = *s++) != 0) {
	switch (c) {
	case '.':
	    break;
	case '+':
	    if (t < te) *t++ = c;
	    flags &= ~O_ACCMODE;
	    flags |= O_RDWR;
	    continue;
	case 'T':
	    threads = parsethreadn(s, (char **)&s);
	    continue;
    case 'L':
	    c = *s++;
	    longdist = 1;
	    if (c >= (int)'0' && c <= (int)'9') {
		windowlog = strtol(s-1, (char **)&s, 10);
		ZSTD_bounds bounds = ZSTD_cParam_getBounds(ZSTD_c_windowLog);
		if (windowlog < bounds.lowerBound){
		    windowlog = bounds.lowerBound;
		    rpmlog(RPMLOG_WARNING, "Invalid long distance matching window log for zstd. Using %i instead.\n", bounds.lowerBound);
		}
		if (windowlog > bounds.upperBound) {
		    windowlog = bounds.upperBound;
		    rpmlog(RPMLOG_WARNING, "Invalid long distance matching window log for zstd. Using %i instead.\n", bounds.upperBound);
		}
   	    }
	    continue;
	default:
	    if (c >= (int)'0' && c <= (int)'9') {
		level = strtol(s-1, (char **)&s, 10);
		ZSTD_bounds bounds = ZSTD_cParam_getBounds(ZSTD_c_compressionLevel);
		if (level < bounds.lowerBound){
		    level = bounds.lowerBound;
		    rpmlog(RPMLOG_WARNING, "Invalid compression level for zstd. Using %i instead.\n", bounds.lowerBound);
		}
		if (level > bounds.upperBound) {
		    level = bounds.upperBound;
		    rpmlog(RPMLOG_WARNING, "Invalid compression level for zstd. Using %i instead.\n", bounds.upperBound);
		}
	    }
	    continue;
	}
	break;
    }
    *t = '\0';

    FILE * fp = fdopen(fdno, stdio);
    if (fp == NULL)
	return NULL;

    zstd = (rpmzstd) xcalloc(1, sizeof(*zstd));
    size_t nb = 0;

    if ((flags & O_ACCMODE) == O_RDONLY) {	/* decompressing */
	if ((zstd->stream.d = ZSTD_createDStream()) == NULL
	 || ZSTD_isError(ZSTD_initDStream(zstd->stream.d))) {
	    goto err;
	}
	nb = ZSTD_DStreamInSize();
    } else {					/* compressing */
	if ((zstd->stream.c = ZSTD_createCCtx()) == NULL
	 || ZSTD_isError(ZSTD_CCtx_setParameter(zstd->stream.c, ZSTD_c_compressionLevel, level))) {
	    goto err;
	}

	if (longdist) {
	    if (ZSTD_isError(ZSTD_CCtx_setParameter(zstd->stream.c, ZSTD_c_enableLongDistanceMatching, longdist))
	     || ZSTD_isError(ZSTD_CCtx_setParameter(zstd->stream.c, ZSTD_c_windowLog, windowlog))) {
	        goto err;
	    }
	}

	if (threads > 0) {
	    if (ZSTD_isError (ZSTD_CCtx_setParameter(zstd->stream.c, ZSTD_c_nbWorkers, threads)))
		rpmlog(RPMLOG_DEBUG, "zstd library does not support multi-threading\n");
	}

	nb = ZSTD_CStreamOutSize();
    }

    zstd->flags = flags;
    zstd->fdno = fdno;
    zstd->level = level;
    zstd->fp = fp;
    zstd->nb = nb;
    zstd->b = (uint8_t *)xmalloc(nb);

    return zstd;

err:
    fclose(fp);
    if ((flags & O_ACCMODE) == O_RDONLY)
	ZSTD_freeDStream(zstd->stream.d);
    else
	ZSTD_freeCCtx(zstd->stream.c);
    return NULL;
}

static rpmzstd zstdFp(FDSTACK_t fps)
{
    return (rpmzstd)fps->fp;
}

static FD_t zstdFdopen(FD_t fd, int fdno, const char * fmode)
{
    rpmzstd zstd = rpmzstdNew(fdno, fmode);

    if (zstd == NULL)
	return NULL;

    fdSetFdno(fd, -1);		/* XXX skip the fdio close */
    fdPush(fd, zstdio, zstd, fdno);		/* Push zstdio onto stack */
    return fd;
}

static int zstdFlush(FDSTACK_t fps)
{
    rpmzstd zstd = zstdFp(fps);
assert(zstd);
    int rc = -1;

    if ((zstd->flags & O_ACCMODE) == O_RDONLY) { /* decompressing */
	rc = 0;
    } else {					/* compressing */
	/* close frame */
	int xx;
	do {
	  ZSTD_inBuffer zib = { NULL, 0, 0 };
	  zstd->zob.dst  = zstd->b;
	  zstd->zob.size = zstd->nb;
	  zstd->zob.pos  = 0;
	  xx = ZSTD_compressStream2(zstd->stream.c, &zstd->zob, &zib, ZSTD_e_flush);
	  if (ZSTD_isError(xx)) {
	      fps->errcookie = ZSTD_getErrorName(xx);
	      break;
	  }
	  else if (zstd->zob.pos != fwrite(zstd->b, 1, zstd->zob.pos, zstd->fp)) {
	      fps->errcookie = "zstdClose fwrite failed.";
	      break;
	  }
	  else
	      rc = 0;
	} while (xx != 0);
    }
    return rc;
}

static ssize_t zstdRead(FDSTACK_t fps, void * buf, size_t count)
{
    rpmzstd zstd = zstdFp(fps);
assert(zstd);
    ZSTD_outBuffer zob = { buf, count, 0 };

    while (zob.pos < zob.size) {
	/* Re-fill compressed data buffer. */
	if (zstd->zib.pos >= zstd->zib.size) {
	    zstd->zib.size = fread(zstd->b, 1, zstd->nb, zstd->fp);
	    if (zstd->zib.size == 0)
		break;		/* EOF */
	    zstd->zib.src  = zstd->b;
	    zstd->zib.pos  = 0;
	}

	/* Decompress next chunk. */
	int xx = ZSTD_decompressStream(zstd->stream.d, &zob, &zstd->zib);
	if (ZSTD_isError(xx)) {
	    fps->errcookie = ZSTD_getErrorName(xx);
	    return -1;
	}
    }
    return zob.pos;
}

static ssize_t zstdWrite(FDSTACK_t fps, const void * buf, size_t count)
{
    rpmzstd zstd = zstdFp(fps);
assert(zstd);
    ZSTD_inBuffer zib = { buf, count, 0 };

    while (zib.pos < zib.size) {

	/* Reset to beginning of compressed data buffer. */
	zstd->zob.dst  = zstd->b;
	zstd->zob.size = zstd->nb;
	zstd->zob.pos  = 0;

	/* Compress next chunk. */
	int xx = ZSTD_compressStream2(zstd->stream.c, &zstd->zob, &zib, ZSTD_e_continue);
	if (ZSTD_isError(xx)) {
	    fps->errcookie = ZSTD_getErrorName(xx);
	    return -1;
	}

	/* Write compressed data buffer. */
        if (zstd->zob.pos > 0) {
	    size_t nw = fwrite(zstd->b, 1, zstd->zob.pos, zstd->fp);
	    if (nw != zstd->zob.pos) {
		fps->errcookie = "zstdWrite fwrite failed.";
		return -1;
	    }
	}
    }
    return zib.pos;
}

static int zstdClose(FDSTACK_t fps)
{
    rpmzstd zstd = zstdFp(fps);
assert(zstd);
    int rc = -2;

    if ((zstd->flags & O_ACCMODE) == O_RDONLY) { /* decompressing */
	rc = 0;
	ZSTD_freeDStream(zstd->stream.d);
    } else {					/* compressing */
	/* close frame */
	int xx;
	do {
	  ZSTD_inBuffer zib = { NULL, 0, 0 };
	  zstd->zob.dst  = zstd->b;
	  zstd->zob.size = zstd->nb;
	  zstd->zob.pos  = 0;
	  xx = ZSTD_compressStream2(zstd->stream.c, &zstd->zob, &zib, ZSTD_e_end);
	  if (ZSTD_isError(xx)) {
	      fps->errcookie = ZSTD_getErrorName(xx);
	      break;
	  }
	  else if (zstd->zob.pos != fwrite(zstd->b, 1, zstd->zob.pos, zstd->fp)) {
	      fps->errcookie = "zstdClose fwrite failed.";
	      break;
	  }
	  else
	      rc = 0;
	} while (xx != 0);
	ZSTD_freeCCtx(zstd->stream.c);
    }

    if (zstd->fp && fileno(zstd->fp) > 2)
	(void) fclose(zstd->fp);

    if (zstd->b) free(zstd->b);
    free(zstd);

    return rc;
}

static const struct FDIO_s zstdio_s = {
  "zstdio", "zstd",
  zstdRead, zstdWrite, NULL, zstdClose,
  NULL, zstdFdopen, zstdFlush, NULL, zfdError, zfdStrerr
};
const FDIO_t zstdio = &zstdio_s ;

#endif	/* HAVE_ZSTD */

/* =============================================================== */

#define	FDIOVEC(_fps, _vec)	\
  ((_fps) && (_fps)->io) ? (_fps)->io->_vec : NULL

const char *Fstrerror(FD_t fd)
{
    const char *err = "";

    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_fstrerr_function_t _fstrerr = FDIOVEC(fps, _fstrerr);
	if (_fstrerr)
	    err = _fstrerr(fps);
    } else if (errno){
	err = strerror(errno);
    }
    return err;
}

ssize_t Fread(void *buf, size_t size, size_t nmemb, FD_t fd)
{
    ssize_t rc = -1;

    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_read_function_t _read = FDIOVEC(fps, read);

	fdstat_enter(fd, FDSTAT_READ);
	do {
	    rc = (_read ? (*_read) (fps, buf, size * nmemb) : -2);
	} while (rc == -1 && errno == EINTR);
	fdstat_exit(fd, FDSTAT_READ, rc);

	if (fd->digests && rc > 0)
	    fdUpdateDigests(fd, buf, rc);
    }

    DBGIO(fd, (stderr, "==>\tFread(%p,%p,%ld) rc %ld %s\n",
	  fd, buf, (long)size * nmemb, (long)rc, fdbg(fd)));

    return rc;
}

ssize_t Fwrite(const void *buf, size_t size, size_t nmemb, FD_t fd)
{
    ssize_t rc = -1;

    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_write_function_t _write = FDIOVEC(fps, write);
	
	fdstat_enter(fd, FDSTAT_WRITE);
	do {
	    rc = (_write ? _write(fps, buf, size * nmemb) : -2);
	} while (rc == -1 && errno == EINTR);
	fdstat_exit(fd, FDSTAT_WRITE, rc);

	if (fd->digests && rc > 0)
	    fdUpdateDigests(fd, buf, rc);
    }

    DBGIO(fd, (stderr, "==>\tFwrite(%p,%p,%ld) rc %ld %s\n",
	  fd, buf, (long)size * nmemb, (long)rc, fdbg(fd)));

    return rc;
}

int Fseek(FD_t fd, off_t offset, int whence)
{
    int rc = -1;

    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_seek_function_t _seek = FDIOVEC(fps, seek);

	fdstat_enter(fd, FDSTAT_SEEK);
	rc = (_seek ? _seek(fps, offset, whence) : -2);
	fdstat_exit(fd, FDSTAT_SEEK, rc);
    }

    DBGIO(fd, (stderr, "==>\tFseek(%p,%ld,%d) rc %lx %s\n",
	  fd, (long)offset, whence, (unsigned long)rc, fdbg(fd)));

    return rc;
}

int Fclose(FD_t fd)
{
    int rc = 0, ec = 0;

    if (fd == NULL)
	return -1;

    fd = fdLink(fd);
    fdstat_enter(fd, FDSTAT_CLOSE);
    for (FDSTACK_t fps = fd->fps; fps != NULL; fps = fdPop(fd)) {
	if (fps->fdno >= 0) {
	    fdio_close_function_t _close = FDIOVEC(fps, close);
	    rc = _close ? _close(fps) : -2;

	    if (ec == 0 && rc)
		ec = rc;
	}

	/* Debugging stats for compresed types */
	if (_rpmio_debug && fps->fdno == -1)
	    fdstat_print(fd, fps->io->ioname, stderr);

	/* Leave freeing the last one after stats */
	if (fps->prev == NULL)
	    break;
    }
    fdstat_exit(fd, FDSTAT_CLOSE, rc);
    DBGIO(fd, (stderr, "==>\tFclose(%p) rc %lx %s\n",
	  (fd ? fd : NULL), (unsigned long)rc, fdbg(fd)));
    fdPop(fd);

    fdFree(fd);
    return ec;
}

/**
 * Convert stdio fmode to open(2) mode, filtering out zlib/bzlib flags.
 *	returns stdio[0] = NUL on error.
 *
 * - gzopen:	[0-9] is compression level
 * - gzopen:	'f' is filtered (Z_FILTERED)
 * - gzopen:	'h' is Huffman encoding (Z_HUFFMAN_ONLY)
 * - bzopen:	[1-9] is block size (modulo 100K)
 * - bzopen:	's' is smallmode
 * - HACK:	'.' terminates, rest is type of I/O
 */
static void cvtfmode (const char *m,
				char *stdio, size_t nstdio,
				char *other, size_t nother,
				const char **end, int * f)
{
    int flags = 0;
    char c;

    switch (*m) {
    case 'a':
	flags &= ~O_ACCMODE;
	flags |= O_WRONLY | O_CREAT | O_APPEND;
	if (--nstdio > 0) *stdio++ = *m;
	break;
    case 'w':
	flags &= ~O_ACCMODE;
	flags |= O_WRONLY | O_CREAT | O_TRUNC;
	if (--nstdio > 0) *stdio++ = *m;
	break;
    case 'r':
	flags &= ~O_ACCMODE;
	flags |= O_RDONLY;
	if (--nstdio > 0) *stdio++ = *m;
	break;
    default:
	*stdio = '\0';
	return;
	break;
    }
    m++;

    while ((c = *m++) != '\0') {
	switch (c) {
	case '.':
	    break;
	case '+':
	    flags &= ~O_ACCMODE;
	    flags |= O_RDWR;
	    if (--nstdio > 0) *stdio++ = c;
	    continue;
	    break;
	case 'b':
	    if (--nstdio > 0) *stdio++ = c;
	    continue;
	    break;
	case 'x':
	    flags |= O_EXCL;
	    if (--nstdio > 0) *stdio++ = c;
	    continue;
	    break;
	case '?':
	    flags |= RPMIO_DEBUG_IO;
	    if (--nother > 0) *other++ = c;
	    continue;
	    break;
	default:
	    if (--nother > 0) *other++ = c;
	    continue;
	    break;
	}
	break;
    }

    *stdio = *other = '\0';
    if (end != NULL)
	*end = (c != '\0' && *m != '\0' ? m : NULL);
    if (f != NULL)
	*f = flags;
}

static FDIO_t findIOT(const char *name)
{
    static FDIO_t fdio_types[] = {
	&fdio_s,
	&ufdio_s,
	&gzdio_s,
#ifdef HAVE_BZLIB_H
	&bzdio_s,
#endif
#ifdef HAVE_LZMA_H
	&xzdio_s,
	&lzdio_s,
#endif
#ifdef HAVE_ZSTD
	&zstdio_s,
#endif
	NULL
    };
    FDIO_t iot = NULL;

    for (FDIO_t *t = fdio_types; t && *t; t++) {
	if (rstreq(name, (*t)->ioname) ||
		((*t)->name && rstreq(name, (*t)->name))) {
	    iot = (*t);
	    break;
	}
    }

    return iot;
}

FD_t Fdopen(FD_t ofd, const char *fmode)
{
    char stdio[20], other[20], stdioz[40];
    const char *end = NULL;
    FDIO_t iot = NULL;
    FD_t fd = ofd;
    int fdno = Fileno(ofd);

if (_rpmio_debug)
fprintf(stderr, "*** Fdopen(%p,%s) %s\n", fd, fmode, fdbg(fd));

    if (fd == NULL || fmode == NULL || fdno < 0)
	return NULL;

    cvtfmode(fmode, stdio, sizeof(stdio), other, sizeof(other), &end, NULL);
    if (stdio[0] == '\0')
	return NULL;
    stdioz[0] = '\0';
    strncat(stdioz, stdio, sizeof(stdioz) - strlen(stdioz) - 1);
    strncat(stdioz, other, sizeof(stdioz) - strlen(stdioz) - 1);

    if (end == NULL && other[0] == '\0')
	return fd;

    if (end && *end) {
	iot = findIOT(end);
    } else if (other[0] != '\0') {
	for (end = other; *end && strchr("0123456789fh", *end); end++)
	    {};
	if (*end == '\0')
	    iot = findIOT("gzdio");
    }

    if (iot && iot->_fdopen)
	fd = iot->_fdopen(fd, fdno, stdioz);

DBGIO(fd, (stderr, "==> Fdopen(%p,\"%s\") returns fd %p %s\n", ofd, fmode, (fd ? fd : NULL), fdbg(fd)));
    return fd;
}

FD_t Fopen(const char *path, const char *fmode)
{
    char stdio[20], other[20];
    const char *end = NULL;
    mode_t perms = 0666;
    int flags = 0;
    FD_t fd = NULL;

    if (path == NULL || fmode == NULL)
	return NULL;

    stdio[0] = '\0';
    cvtfmode(fmode, stdio, sizeof(stdio), other, sizeof(other), &end, &flags);
    if (stdio[0] == '\0')
	return NULL;

    if (end == NULL || rstreq(end, "fdio")) {
	if (_rpmio_debug)
	    fprintf(stderr, "*** Fopen fdio path %s fmode %s\n", path, fmode);
	fd = fdOpen(path, flags, perms);
    } else {
	if (_rpmio_debug)
	    fprintf(stderr, "*** Fopen ufdio path %s fmode %s\n", path, fmode);
	fd = ufdOpen(path, flags, perms);
    }

    /* Open compressed stream if necessary */
    if (fd)
	fd = Fdopen(fd, fmode);

    DBGIO(fd, (stderr, "==>\tFopen(\"%s\",%x,0%o) %s\n",
	  path, (unsigned)flags, (unsigned)perms, fdbg(fd)));

    return fd;
}

int Fflush(FD_t fd)
{
    int rc = -1;
    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_fflush_function_t _fflush = FDIOVEC(fps, _fflush);

	rc = (_fflush ? _fflush(fps) : -2);
    }
    return rc;
}

off_t Ftell(FD_t fd)
{
    off_t pos = -1;
    if (fd != NULL) {
	FDSTACK_t fps = fdGetFps(fd);
	fdio_ftell_function_t _ftell = FDIOVEC(fps, _ftell);

	pos = (_ftell ? _ftell(fps) : -2);
    }
    return pos;
}

int Ferror(FD_t fd)
{
    int rc = 0;

    if (fd == NULL) return -1;
    for (FDSTACK_t fps = fd->fps; fps != NULL; fps = fps->prev) {
	fdio_ferror_function_t _ferror = FDIOVEC(fps, _ferror);
	rc = _ferror(fps);

	if (rc)
	    break;
    }
DBGIO(fd, (stderr, "==> Ferror(%p) rc %d %s\n", fd, rc, fdbg(fd)));
    return rc;
}

int Fileno(FD_t fd)
{
    int rc = -1;

    if (fd == NULL) return -1;
    for (FDSTACK_t fps = fd->fps; fps != NULL; fps = fps->prev) {
	rc = fps->fdno;
	if (rc != -1)
	    break;
    }
    
DBGIO(fd, (stderr, "==> Fileno(%p) rc %d %s\n", (fd ? fd : NULL), rc, fdbg(fd)));
    return rc;
}

/* XXX this is naive */
int Fcntl(FD_t fd, int op, void *lip)
{
    return fcntl(Fileno(fd), op, lip);
}

rpmop fdOp(FD_t fd, fdOpX opx)
{
    rpmop op = NULL;

    if (fd != NULL && fd->stats != NULL && opx >= 0 && opx < FDSTAT_MAX)
        op = fd->stats->ops + opx;
    return op;
}

int rpmioSlurp(const char * fn, uint8_t ** bp, ssize_t * blenp)
{
    static const ssize_t blenmax = (32 * BUFSIZ);
    ssize_t blen = 0;
    uint8_t * b = NULL;
    ssize_t size;
    FD_t fd;
    int rc = 0;

    fd = Fopen(fn, "r.ufdio");
    if (fd == NULL || Ferror(fd)) {
	rc = 2;
	goto exit;
    }

    size = fdSize(fd);
    blen = (size >= 0 ? size : blenmax);
    if (blen) {
	int nb;
	b = (uint8_t *)xmalloc(blen+1);
	b[0] = '\0';
	nb = Fread(b, sizeof(*b), blen, fd);
	if (Ferror(fd) || (size > 0 && nb != blen)) {
	    rc = 1;
	    goto exit;
	}
	if (blen == blenmax && nb < blen) {
	    blen = nb;
	    b = xrealloc(b, blen+1);
	}
	b[blen] = '\0';
    }

exit:
    if (fd) (void) Fclose(fd);
	
    if (rc) {
	if (b) free(b);
	b = NULL;
	blen = 0;
    }

    if (bp) *bp = b;
    else if (b) free(b);

    if (blenp) *blenp = blen;

    return rc;
}

void fdInitDigest(FD_t fd, int hashalgo, rpmDigestFlags flags)
{
    return fdInitDigestID(fd, hashalgo, hashalgo, flags);
}

void fdInitDigestID(FD_t fd, int hashalgo, int id, rpmDigestFlags flags)
{
    if (fd->digests == NULL) {
	fd->digests = rpmDigestBundleNew();
    }
    fdstat_enter(fd, FDSTAT_DIGEST);
    rpmDigestBundleAddID(fd->digests, hashalgo, id, flags);
    fdstat_exit(fd, FDSTAT_DIGEST, (ssize_t) 0);
}

static void fdUpdateDigests(FD_t fd, const void * buf, size_t buflen)
{
    if (fd && fd->digests) {
	fdstat_enter(fd, FDSTAT_DIGEST);
	rpmDigestBundleUpdate(fd->digests, buf, buflen);
	fdstat_exit(fd, FDSTAT_DIGEST, (ssize_t) buflen);
    }
}

void fdFiniDigest(FD_t fd, int id,
		void ** datap, size_t * lenp, int asAscii)
{
    if (fd && fd->digests) {
	fdstat_enter(fd, FDSTAT_DIGEST);
	rpmDigestBundleFinal(fd->digests, id, datap, lenp, asAscii);
	fdstat_exit(fd, FDSTAT_DIGEST, (ssize_t) 0);
    }
}

DIGEST_CTX fdDupDigest(FD_t fd, int id)
{
    DIGEST_CTX ctx = NULL;

    if (fd && fd->digests)
	ctx = rpmDigestBundleDupCtx(fd->digests, id);

    return ctx;
}

static void set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags == -1 || (flags & FD_CLOEXEC))
	return;

    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

void rpmSetCloseOnExec(void)
{
    const int min_fd = STDERR_FILENO; /* don't touch stdin/out/err */
    int fd;

    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL) { /* /proc not available */
	/* iterate over all possible fds, might be slow */
	struct rlimit rl;
	int open_max;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY)
	    open_max = rl.rlim_max;
	else
	    open_max = sysconf(_SC_OPEN_MAX);

	if (open_max == -1)
	    open_max = 1024;

	for (fd = min_fd + 1; fd < open_max; fd++)
	    set_cloexec(fd);

	return;
    }

    /* iterate over fds obtained from /proc */
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
	fd = atoi(entry->d_name);
	if (fd > min_fd)
	    set_cloexec(fd);
    }

    closedir(dir);

    return;
}
