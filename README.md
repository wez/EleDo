# de-elevate your process

This crate helps to reduce the privilege level of the calling code on Windows systems.

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

* Detecting increased privileges, including both *Elevation* and High Integrity
  Administrative privs, so that the embedding application can choose whether
  to surface this as an error, or to continue with the second half of the crate...
* Re-executing the application with reduced privs, while passing the stdio
  streams and process exit status back to the original parent.

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
