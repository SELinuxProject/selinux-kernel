SELinux Kernel Subsystem
=============================================================================
https://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/selinux.git  
https://github.com/SELinuxProject/selinux-kernel

SELinux is a security enhancement to Linux which provides users and
administrators a more granular, powerful access control mechanism.  It consists
of a kernel component which enforces the security policy, a set of userspace
tools to manage and manipulate SELinux security policies, and the SELinux
security policies themselves.

The main Linux Kernel README can be found at
[Documentation/admin-guide/README.rst](./Documentation/admin-guide/README.rst)

## Online Resources

The canonical SELinux kernel repository is hosted by kernel.org:

* https://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/selinux.git
* git://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/selinux.git

There is also an officially maintained GitHub mirror:

* https://github.com/SELinuxProject/selinux-kernel

## Kernel Source Branches and Development Process

### Kernel Source Branches

There are four primary git branches associated with the development process:
stable-X.Y, dev, dev-staging, and next.  In addition to these four primary
branches there are also topic specific, work in progress branches that start
with a "working-" prefix; these branches can generally be ignored unless you
happen to be involved in the development of that particular topic.  The
management of these topic branches can vary depending on a number of factors,
but the details of each branch will be communicated in the relevant discussion
threads on the upstream mailing list.

#### stable-X.Y branch

The stable-X.Y branch is intended for stable kernel patches and is based on
Linus' X.Y-rc1 tag, or a later X.Y.Z stable kernel release tag as needed.
If serious problems are identified and a patch is developed during the kernel's
release candidate cycle, it may be a candidate for stable kernel marking and
inclusion into the stable-X.Y branch.  The main Linux kernel's documentation
on stable kernel patches has more information both on what patches may be
stable kernel candidates, and how to mark those patches appropriately; upstream
mailing list discussions on the merits of marking the patch for stable can also
be expected.  Once a patch has been merged into the stable-X.Y branch and spent
a day or two in the next branch (see the next branch notes), it will be sent to
Linus for merging into the next release candidate or final kernel release (see
the notes on pull requests in this document).  If the patch has been properly
marked for stable, the other stable kernel trees will attempt to backport the
patch as soon as it is present in Linus' tree, see the main Linux kernel
documentation for more details.

Unless specifically requested, developers should not base their patches on the
stable-X.Y branch.  Any merge conflicts that arise from merging patches
submitted upstream will be handled by the maintainer, although help and/or may
be requested in extreme cases.

#### dev branch

The dev branch is intended for development patches targeting the upcoming merge
window, and is based on Linus' latest X.Y-rc1 tag, or a later rc tag as needed
to avoid serious bugs, merge conflicts, or other significant problems.  This
branch is the primary development branch where the majority of patches are
merged during the normal kernel development cycle.  Patches merged into the
dev branch will be present in the next branch (see the next branch notes) and
will be sent to Linus during the next merge window.

Developers should use the dev branch as a stable basis for their own
development work, only under extreme circumstances will the dev branch be
rebased during the X.Y-rc cycle and the maintainer will be responsible for
resolving any merge conflicts, although help and/or may be requested in extreme
cases.

#### dev-staging branch

The dev-staging branch is intended for development patches that are not
targeting a specific merge window.  The dev-staging branch exists as a staging
area for the main dev branch and as such its use will be unpredictable and it
will be rebased as needed.  Patches merged into the dev-staging branch should
find their way into the primary dev branch at some point in the future,
although that is not guaranteed.

Unless specifically requested, developers should not use the dev-staging branch
as a basis for any development work.

#### next branch

The next branch is a composite branch built by merging the latest stable-X.Y
and dev branches in that order.  The main focus of the next branch is to
provide a single branch for linux-next integration testing that contains all of
the commits from the component branches.  The next branch will be updated
whenever there is a change to any one of the component branches, but it will
remain frozen during the merge window so as to cooperate with the wishes of the
linux-next team.

While developers can use the next branch as a basis for development, the dev
branch would likely be a more suitable, and stable, base.

### Kernel Development Process

After Linus closes the kernel merge window upstream, the stable-X.Y branch
associated with the current kernel release candidate, the dev branch, and
potentially the dev-staging branch (see the dev-staging branch notes) will be
reset to match the latest vX.Y-rc1 tag in Linus' tree.  The next branch, as a
composite branch composed from these branches, will be updated as a result.

During the development cycle that starts with the close of the kernel merge
window and ends with the tagged kernel release, patches will be accepted into
the stable-X.Y and dev branches as described in their respective sections in
this document.  While patches will be accepted into the stable-X.Y branch at
any point in time, significant changes will likely not be accepted into the dev
branch when there are two or less weeks left in the development cycle; this
typically means that only critical bugfixes are accepted once the vX.Y-rc6
kernel is released.  During this time the next branch will be regenerated on an
as needed basis based on changes in the component branches, and pull requests
will be sent as needed to Linus for patches in the stable-X.Y branch.

Once Linus releases the final vX.Y kernel and the merge window opens, two
things will happen.  The first is that the dev branch will be duplicated into
a new stable-X'.Y' branch, representing the new upcoming kernel release, and
the second is that a pull request will be sent from this branch for inclusion
into the current merge window.  During the merge window process the dev and
next branches should be frozen, although there is a possibility that some
patches may be merged into dev-staging for testing or process related reasons.

#### Pull Requests for Linus

In order to send a pull request to Linus, either for a critical bugfix or as
part of the merge window, a signed git tag must be created that points to the
pull request point.  The tag should be named using the "{subsystem}-pr-{date}"
format and can be generated with the following git command:

```
% git tag -s -m "{subsystem}/stable-X'.Y' PR {date}" {subsystem}-pr-{date}
```

Once the signed tag has been created, it should be used as the basis for the
pull request.

## Reference Policy, Userspace Tools, and Test Suites

The SELinux reference policy, userspace tools, and test suites are hosted by
GitHub:

* https://github.com/SELinuxProject
