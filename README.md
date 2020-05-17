# (de-)elevate your process

This crate helps to reduce or increase the privilege level of the calling code
on Windows systems.

The target audience is owners of stateful tools or services that humans interact
with on the local system and where those tools/service are intended generally
intended to run as that human at their normal privilege level.

It is not intended to be used in a multi-tenant situation where there are
multiple user tokens in use.

## Why?

With folks running a combination of elevated powershells and regular command or
msys windows, it is reasonably likely that the mix of privileges in different
contexts will result in permission related problems that result in weird or
hard to debug problems and end up costing people time.

## How do I use it?

There are two logical halves to this crate;

* Detecting the privilege level, including both *Elevation* and High Integrity
  Administrative privs, so that the embedding application can choose whether
  to surface this as an error, or to continue with the second half of the crate...

```rust
use deelevate::*;

let token = Token::with_current_process()?;
match token.privilege_level()? {
  PrivilegeLevel::NotPrivileged => {
    // No special privs
  }
  PrivilegeLevel::Elevated => {
    // Invoked via runas
  }
  PrivilegeLevel::HighIntegrityAdmin => {
    // Some other kind of admin priv.
    // For example: ssh session to Windows 10 SSH server
  }
}
```

* Re-executing the application with altered privs, while passing the stdio
  streams and process exit status back to the original parent.

```rust
use deelevate::spawn_with_reduced_privileges;
use deelevate::spawn_with_elevated_privileges;

// If we have admin privs, this next line will either spawn a version
// of the current process with reduced privs, or yield an error trying
// to do that.
// The spawn_with_elevated_privileges function works similarly, except
// that it will only return when the calling process has elevated
// privs.
spawn_with_reduced_privileges()?;

// If we reach this line it is because we don't have any special privs
// and we can therefore continue with our normal operation.
```

The `show` example demonstrates testing for the privilege level.

The `spawn` example demonstrates re-executing the process at a lower priv level.

## Caveats?

There are some privilege levels that are not mapped as privileged from the
perspective of this crate.  The rationale for this is that those levels are
unusual enough that they are probably not humans and probably should not have
this crate adjusting the privilege level.

It may feel like this might be a security concern, but its worth noting that:

* The calling code already has equal or higher privilege (so no escalation is possible)
* This crate is intended for convenience and consistency for human users

## Bonus Utilities

This crate provides `normdo.exe` for running a command with normal privileges,
and `eledo.exe` for running a command with elevated privileges.  Unlike other
elevation solutions, both of these utilities are designed to run from inside
a console and to keep the output from the target application in that console.
In addition, these tools use the PTY APIs in order to support running terminal
applications such as pagers and editors (vim.exe!) correctly!

### `eledo.exe`

*Runs a program with elevated privs*

```
eledo.exe PROGRAM [ARGUMENTS]
```

`eledo.exe` will check to see if the current context has admin privileges;
if it does then it will execute the requested `PROGRAM` directly, returning
its exit status.

Otherwise, `eledo.exe` will arrange to run the program with an elevated PTY
that is bridged to the current terminal session.  Elevation requires that the
current process be able to communicate with the shell in the current desktop
session, and will typically trigger a UAC prompt for that user.

```
> eledo.exe whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

### `normdo.exe`

*Runs a program with normal privs*

```
normdo.exe PROGRAM [ARGUMENTS]
```

`normdo.exe` will check to see if the current context has admin privileges;
if it does *not* then it will execute the requested `PROGRAM` directly, returning
its exit status.

Otherwise, `eledo.exe` will arrange to run the program with a Normal user token
with Medium integrity level, dropping/denying the local administrator group
from the current token.  The program will be run in a PTY that is bridged to
the current terminal session.

```
> normdo.exe whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```
