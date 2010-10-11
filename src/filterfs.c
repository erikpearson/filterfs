/*
  FilterFS: Filter Filesystem

  Copyright (C) 2010
    Gregor Zurowski <gregor.zurowski@lunetta.net>
    Kristofer Henriksson <kthenriksson@gmail.com>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` filterfs.c -o filterfs
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fnmatch.h>
#include <fuse.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define ffs_debug(f, ...) syslog(LOG_DEBUG, f, ## __VA_ARGS__)
#define ffs_info(f, ...) syslog(LOG_INFO, f, ## __VA_ARGS__)
#define ffs_error(f, ...) syslog(LOG_ERR, f, ## __VA_ARGS__)

int default_exclude = 0;
int debug = 0;
char *srcdir = NULL;

enum {
    KEY_EXCLUDE,
    KEY_INCLUDE,
    KEY_DEFAULT_EXCLUDE,
    KEY_DEFAULT_INCLUDE,
    KEY_HELP,
    KEY_VERSION,
    KEY_KEEP_OPT
};

static struct fuse_opt ffs_opts[] = {
    FUSE_OPT_KEY("-X %s",                   KEY_EXCLUDE),
    FUSE_OPT_KEY("--exclude=%s",            KEY_EXCLUDE),
    FUSE_OPT_KEY("exclude=%s",              KEY_EXCLUDE),
    FUSE_OPT_KEY("-I %s",                   KEY_INCLUDE),
    FUSE_OPT_KEY("--include=%s",            KEY_INCLUDE),
    FUSE_OPT_KEY("include=%s",              KEY_INCLUDE),
    FUSE_OPT_KEY("--default-exclude",       KEY_DEFAULT_EXCLUDE),
    FUSE_OPT_KEY("--default-include",       KEY_DEFAULT_INCLUDE),
    FUSE_OPT_KEY("-d",                      KEY_KEEP_OPT),
    FUSE_OPT_KEY("--debug",                 KEY_KEEP_OPT),

    FUSE_OPT_KEY("-h",            KEY_HELP),
    FUSE_OPT_KEY("--help",        KEY_HELP),
    FUSE_OPT_KEY("-V",            KEY_VERSION),
    FUSE_OPT_KEY("--version",     KEY_VERSION),
    FUSE_OPT_END
};

struct rule {
    char *pattern;
    int exclude;
    struct rule *next;
};

struct {
    struct rule *head;
    struct rule *tail;
} chain;


/**
 * Appends a single rule to the filter chain.
 */
static int append_rule(char *pattern, int exclude)
{
    struct rule *rule = malloc(sizeof(struct rule));

    if (!rule)
        return -1;

    rule->pattern = pattern;
    rule->exclude = exclude;
    rule->next = NULL;

    if (!chain.head) {
        chain.head = rule;
        chain.tail = rule;
    }
    else {
        chain.tail->next = rule;
        chain.tail = rule;
    }

    return 0;
}

/**
 * Appends multiple rules to the filter chain.
 */
static int append_rules(char *patterns, int exclude)
{
    char *str = patterns;

    while (1) {
        if (append_rule(str, exclude) == -1)
            return -1;
        
        if (!(str = strchr(str, ':')))
            break;

        *str = '\0';
        str++;
    }

    return 0;
}

/**
 * Checks whether the provided path should be excluded.
 */
static int exclude_path(const char *path)
{
    struct stat st;
    lstat(path, &st);

    /* directories must not be filtered (currently) */
    if (S_ISDIR(st.st_mode))
        return 0;

    /* we only need the last part of the path */
    char *path_tail = strrchr(path, '/');
    if (path_tail == NULL)
        *path_tail = *path;
    else
        path_tail++;

    struct rule *curr_rule = chain.head;

    while (curr_rule) {
        if (fnmatch(curr_rule->pattern, path_tail, 0) == 0) {
            return curr_rule->exclude;
        }
        curr_rule = curr_rule->next;
    }

    return default_exclude;
}

/**
 * Checks if str1 begins with str2. If so, returns a pointer to the end of
 * the match. Otherwise, returns null.
 */
static const char *str_consume(const char *str1, char *str2)
{
    if (strncmp(str1, str2, strlen(str2)) == 0) {
        return str1 + strlen(str2);
    }

    return 0;
}

/*
 * FUSE callback operations
 */
static int ffs_getattr(const char *path, struct stat *stbuf)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));
    
    int exclude = exclude_path(xpath);

    ffs_debug("getattr: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;
    res = lstat(xpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_access(const char *path, int mask)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);
    
    ffs_debug("access: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;
    res = access(xpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_readlink(const char *path, char *buf, size_t size)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("readlink: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;
    res = readlink(xpath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int ffs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;

    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("readdir[1]: path %s (expanded %s), exclude: %s\n", path,
xpath, exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    dp = opendir(xpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        strncpy(xpath, srcdir, sizeof(xpath));
        strncat(xpath, "/", sizeof(xpath) - 1);
        strncat(xpath, de->d_name, sizeof(xpath) - strlen(xpath));

        exclude = exclude_path(xpath);

        ffs_debug("readdir[2]: path %s (expanded %s), exclude: %s\n",
de->d_name, xpath, exclude ? "y" : "n");

        if (exclude)
            continue;

        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int ffs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("mknod: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(xpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(xpath, mode);
    else
        res = mknod(xpath, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_mkdir(const char *path, mode_t mode)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("mkdir: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = mkdir(xpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_unlink(const char *path)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("unlink: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = unlink(xpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_rmdir(const char *path)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("rmdir: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;
    res = rmdir(xpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_symlink(const char *from, const char *to)
{
    char xfrom[PATH_MAX];

    strncpy(xfrom, srcdir, sizeof(xfrom));
    if (from[0] != '/')
        strncat(xfrom, "/", sizeof(xfrom) - 1);
    strncat(xfrom, from, sizeof(xfrom) - strlen(xfrom));
    
    char xto[PATH_MAX];
    strncpy(xto, srcdir, sizeof(xto));
    strncat(xto, to, sizeof(xto) - strlen(xto));

    int exclude_from = exclude_path(xfrom);
    int exclude_to = exclude_path(xto);

    ffs_debug("symlink: from %s (expanded %s), exclude %s; to %s (expanded %s),"
" exclude %s\n", from, xfrom, exclude_from ? "y" : "n", to, xto, exclude_to ?
"y": "n");
    
    if (exclude_from || exclude_to)
        return -ENOENT;

    int res;
    res = symlink(from, xto);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_rename(const char *from, const char *to)
{
    char xfrom[PATH_MAX];
    strncpy(xfrom, srcdir, sizeof(xfrom));
    if (from[0] != '/')
        strncat(xfrom, "/", sizeof(xfrom) - 1);
    strncat(xfrom, from, sizeof(xfrom) - strlen(xfrom));

    char xto[PATH_MAX];
    strncpy(xto, srcdir, sizeof(xto));
    strncat(xto, to, sizeof(xto) - strlen(xto));

    int exclude_from = exclude_path(xfrom);
    int exclude_to = exclude_path(xto);

    ffs_debug("rename: from %s (expanded %s), exclude %s; to %s (expanded %s),"
" exclude %s\n", from, xfrom, exclude_from ? "y" : "n", to, xto, exclude_to ?
"y": "n");
    
    if (exclude_from || exclude_to)
        return -ENOENT;

    int res;
    res = rename(xfrom, xto);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_link(const char *from, const char *to)
{
    char xfrom[PATH_MAX];
    strncpy(xfrom, srcdir, sizeof(xfrom));
    if (from[0] != '/')
        strncat(xfrom, "/", sizeof(xfrom) - 1);
    strncat(xfrom, from, sizeof(xfrom) - strlen(xfrom));

    char xto[PATH_MAX];
    strncpy(xto, srcdir, sizeof(xto));
    strncat(xto, to, sizeof(xto) - strlen(xto));

    int exclude_from = exclude_path(xfrom);
    int exclude_to = exclude_path(xto);

    ffs_debug("link: from %s (expanded %s), exclude %s; to %s (expanded %s),"
" exclude %s\n", from, xfrom, exclude_from ? "y" : "n", to, xto, exclude_to ?
"y": "n");
    
    if (exclude_from || exclude_to)
        return -ENOENT;

    int res;
    res = link(xfrom, xto);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_chmod(const char *path, mode_t mode)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("chmod: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = chmod(xpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_chown(const char *path, uid_t uid, gid_t gid)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("chown: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = lchown(xpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_truncate(const char *path, off_t size)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("truncate: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = truncate(xpath, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_utimens(const char *path, const struct timespec ts[2])
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("utimens: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(xpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_open(const char *path, struct fuse_file_info *fi)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("open: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res;
    res = open(xpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int ffs_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("read: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int fd;
    int res;

    fd = open(xpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int ffs_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("write: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    ffs_debug("write: path %s (expanded %s)\n", path, xpath);
    
    if (exclude)
        return -ENOENT;

    int fd;
    int res;

    fd = open(xpath, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int ffs_statfs(const char *path, struct statvfs *stbuf)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("statfs: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res;
    res = statvfs(xpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int ffs_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    return 0;
}

static int ffs_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional */
static int ffs_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("setxattr: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");

    if (exclude)
        return -ENOENT;

    int res = lsetxattr(xpath, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int ffs_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("getxattr: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res = lgetxattr(xpath, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int ffs_listxattr(const char *path, char *list, size_t size)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("listxattr: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res = llistxattr(xpath, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int ffs_removexattr(const char *path, const char *name)
{
    char xpath[PATH_MAX];
    strncpy(xpath, srcdir, sizeof(xpath));
    strncat(xpath, path, sizeof(xpath) - strlen(xpath));

    int exclude = exclude_path(xpath);

    ffs_debug("removexattr: path %s (expanded %s), exclude %s\n", path, xpath,
exclude ? "y" : "n");
    
    if (exclude)
        return -ENOENT;

    int res = lremovexattr(xpath, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations ffs_oper = {
    .getattr    = ffs_getattr,
    .access     = ffs_access,
    .readlink   = ffs_readlink,
    .readdir    = ffs_readdir,
    .mknod      = ffs_mknod,
    .mkdir      = ffs_mkdir,
    .symlink    = ffs_symlink,
    .unlink     = ffs_unlink,
    .rmdir      = ffs_rmdir,
    .rename     = ffs_rename,
    .link       = ffs_link,
    .chmod      = ffs_chmod,
    .chown      = ffs_chown,
    .truncate   = ffs_truncate,
    .utimens    = ffs_utimens,
    .open       = ffs_open,
    .read       = ffs_read,
    .write      = ffs_write,
    .statfs     = ffs_statfs,
    .release    = ffs_release,
    .fsync      = ffs_fsync,
#ifdef HAVE_SETXATTR
    .setxattr   = ffs_setxattr,
    .getxattr   = ffs_getxattr,
    .listxattr  = ffs_listxattr,
    .removexattr    = ffs_removexattr,
#endif
};

static void usage(const char *progname)
{
    fprintf(stderr,
        "\nusage: %s sourcedir mountpoint [options]\n"
        "\n"
        "general options:\n"
        "    -o opt,[opt...]        mount options\n"
        "    -h   --help            print help\n"
        "    -V   --version         print version\n"
        "\n"
        "FilterFS options:\n"
        "    -X, --exclude=pattern:[pattern...]    "
        "patterns for files to be excluded\n"
        "    -I, --include=pattern:[pattern...]    "
        "patterns for files to be included\n"
        "    --default-exclude                     "
        "exclude unmatched items (default)\n"
        "    --default-include                     "
        "include unmatched items\n"
        "    --dirs                                "
        "include directories in filtering\n"
        "    --no-dirs                             "
        "exclude directories from filtering (default)\n"
        "\n", progname);
}

static int ffs_opt_proc(void *data, const char *arg, int key,
                        struct fuse_args *outargs)
{
    const char *str;

    switch(key) {
        case FUSE_OPT_KEY_NONOPT:
            // first non-option parameter is source directory
            if (!srcdir) {
                srcdir = strdup(arg);
                return 0;
            }
            break;

        case KEY_EXCLUDE:
            if (!(str = str_consume(arg, "--exclude="))
                && !(str = str_consume(arg, "exclude="))
                && !(str = str_consume(arg, "-X ")))
                return -1;

            /*
             * Not actually a memory leak. We don't want this memory
             * deallocated until program exit.
             */
            if (strlen(str) > 0)
                append_rules(strdup(str), 1);
            
            return 0;

        case KEY_INCLUDE:
            if (!(str = str_consume(arg, "--include="))
                && !(str = str_consume(arg, "include="))
                && !(str = str_consume(arg, "-I ")))
                return -1;

            /* See comment for KEY_EXCLUDE above. */
            if (strlen(str) > 0)
                append_rules(strdup(str), 0);

            return 0;

        case KEY_DEFAULT_EXCLUDE:
            default_exclude = 1;
            return 0;

        case KEY_DEFAULT_INCLUDE:
            default_exclude = 0;
            return 0;

        case KEY_HELP:
            usage(outargs->argv[0]);
            fuse_opt_add_arg(outargs, "-ho");
            fuse_main(outargs->argc, outargs->argv, &ffs_oper, NULL);
            exit(1);

        case KEY_VERSION:
            printf("FilterFS version %s\n", "1.0");
            fuse_opt_add_arg(outargs, "--version");
            fuse_main(outargs->argc, outargs->argv, &ffs_oper, NULL);
            exit(0);

        case KEY_KEEP_OPT:
            return 1;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, NULL, ffs_opts, ffs_opt_proc)) {
        fprintf(stderr, "error: general error while parsing options.\n");
        usage(argv[0]);
        return 1;
    }

    if (!srcdir) {
        fprintf(stderr, "error: no source directory specified.\n");
        usage(argv[0]);
        return 1;
    }

    if (!srcdir || srcdir[0] != '/') {
        fprintf(stderr, "error: source directory must be an absolute path.\n");
        usage(argv[0]);
        return 1;
    }

    struct stat st;
    if (stat(srcdir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: source directory path does not exist or "
        "is not a directory.\n");
        usage(argv[0]);
        return 1;
    }

    if (!chain.head) {
        fprintf(stderr, "error: no filter expressions provided.\n");
        usage(argv[0]);
        return 1;
    }

    /* Log to the screen if debug is enabled. */
    openlog("filterfs", debug ? LOG_PERROR : 0, LOG_USER);

    /* Log startup information */
    ffs_info("source dir: %s\n", srcdir);
    ffs_info("default action: %s\n", default_exclude ? "exclude" :
"include");

    struct rule *curr_rule = chain.head;
    int i = 1;
    while (curr_rule) {
        ffs_info("filter %d: %s %s\n", i++, curr_rule->exclude ? "exclude" :
"include", curr_rule->pattern);
        curr_rule = curr_rule->next;
    }
    
    umask(0);
    int ret = fuse_main(args.argc, args.argv, &ffs_oper, NULL);

    return ret;
}
