"""
rönti sitecustomize hook.
Drop this into a venv's site-packages to intercept pip installs inside that venv.
Installed automatically by `ronti inject-venv <path>`.

Works by monkey-patching pip's post-install wheel recording.
"""
import sys
import os


def _install_hook():
    try:
        import pip._internal.operations.install.wheel as _wheel_mod
        _orig_install = _wheel_mod.install_wheel

        def _patched_install(*args, **kwargs):
            result = _orig_install(*args, **kwargs)
            name = args[0] if args else kwargs.get("name", "")
            try:
                import importlib.metadata as meta
                version = meta.version(name)
                from ronti.logger import log_install
                from ronti.db import get_conn
                log_install(name, version)
                with get_conn() as conn:
                    hits = conn.execute(
                        "SELECT severity, description, cve FROM advisories"
                        " WHERE package=? AND (bad_version=? OR bad_version IS NULL)",
                        (name.lower(), version)
                    ).fetchall()
                if hits:
                    for h in hits:
                        msg = f"[rönti] ⚠  {name}=={version} [{h['severity'].upper()}]: {h['description']}"
                        if h["cve"]:
                            msg += f"  ({h['cve']})"
                        print(msg, file=sys.stderr)
            except Exception:
                pass
            return result

        _wheel_mod.install_wheel = _patched_install
    except Exception:
        pass


if os.environ.get("RONTI_DISABLE", "").lower() not in ("1", "true", "yes"):
    _install_hook()