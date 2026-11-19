# Controlled Docker Sandbox

This package runs only repository-owned `CONTROLLED_MOCK` fixtures through the
fixed `mock_harness.py`. The runner pins an immutable local image ID, uses a
non-root UID/GID, network NONE, read-only root and bind mounts, bounded tmpfs,
dropped capabilities, no-new-privileges, seccomp/AppArmor, and CPU, memory, PID,
file-descriptor, and wall-clock limits. Evidence is returned through stdout;
there is no writable host output mount.

The harness schema can record mock actions but cannot import a Skill, execute a
requested process, or open a socket. Public, unlabeled, symlinked, oversized, or
out-of-root fixtures are rejected.
