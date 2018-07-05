This is some background information about the Linux Auditing Framework.

LICENSE
=======
The audit daemon is released as GPL'd code. The audit daemon's libraries
libaudit.* and libauparse.* are released under LGPL so that it may be
linked with 3rd party software.

BUILDING
========
See the README-install File.

USAGE
=====
See the man pages for audit, auditctl, audit.rules, ausearch, and aureport.

DISCUSSION
==========
Original lkml thread(s): 
     http://marc.theaimsgroup.com/?t=107815888100001&r=1&w=2
     http://marc.theaimsgroup.com/?t=107901570800002&r=1&w=2

There is a linux audit mail list where any question whether kernel design,
setup and configuration, or usage can be discussed:
http://www.redhat.com/mailman/listinfo/linux-audit


DESIGN INFO (Very old)
=====================
The main goals were to provide system call auditing with 1) as low
overhead as possible, and 2) without duplicating functionality that is
already provided by SELinux (and/or other security infrastructures).
This framework will work "stand-alone", but is not designed to provide,
e.g., CAPP functionality without another security component in place.

There are two main parts, one that is always on (generic logging in
audit.c) and one that you can disable at boot- or run-time
(per-system-call auditing in auditsc.c).  The patch includes changes to
security/selinux/avc.c as an example of how system-call auditing can be
integrated with other code that identifies auditable events.

Logging:
    1) Uses a netlink socket for communication with user-space.  All
       messages are logged via the netlink socket if a user-space daemon
       is listening.  If not, the messages are logged via printk to the
       syslog daemon (by default).
    2) Messages can be dropped (optionally) based on message rate or
       memory use (this isn't fully integrated into the selinux/avc.c
       part of the patch: the avc.c code that currently does this can be
       eliminated).
    3) When some part of the kernel generates part of an audit record,
       the partial record is sent immediately to user-space, AND the
       system call "auditable" flag is automatically set for that call
       -- thereby producing extra information at syscall exit (if
       syscall auditing is enabled).

System-call auditing:
    1) At task-creation time, an audit context is allocated and linked
       off the task structure.
    2) At syscall entry time, if the audit context exists, information
       is filled in (syscall number, timestamp; but not arguments).
    3) During the system call, calls to getname() and path_lookup() are
       intercepted.  These routines are called when the kernel is
       actually looking up information that will be used to make the
       decision about whether the syscall will succeed or fail.  An
       effort has been made to avoid copying the information that
       getname generates, since getname is already making a
       kernel-private copy of the information.  [Note that storing
       copies of all syscall arguments requires complexity and overhead
       that arguably isn't needed.  With this patch, for example, if
       chroot("foo") fails because you are not root, "foo" will not
       appear in the audit record because the kernel determined the
       syscall cannot proceed before it ever needed to look up "foo".
       This approach avoids storing user-supplied information that could
       be misleading or unreliable (e.g., due to a cooperative
       shared-memory attack) in favor of reporting information actually
       used by the kernel.]
    4) At syscall exit time, if the "auditable" flag has been set (e.g.,
       because SELinux generated an avc record; or some other part of
       the kernel detected an auditable event), the syscall-part of the
       audit record is generated, including file names and inode numbers
       (if available).  Some of this information is currently
       complementary to the information that selinux/avc.c generates
       (e.g., file names and some inode numbers), but some is less
       complete (e.g., getname doesn't return a fully-qualified path,
       and this patch does not add the overhead of determining one).
       [Note that the complete audit record comes to userspace in
       pieces, which eliminates the need to store messages for
       arbitrarily long periods inside the kernel.]
    5) At task-exit time, the audit context is destroyed.

    At steps 1, 2, and 4, simple filtering can be done (e.g., a database
    role uid might have syscall auditing disabled for performance
    reasons).  The filtering is simple and could be made more complex.
    However, I tried to implement as much filtering as possible without
    adding significant overhead (e.g., d_path()).  In general, the audit
    framework should rely on some other kernel component (e.g., SELinux)
    to make the majority of the decisions about what is and is not
    auditable.
