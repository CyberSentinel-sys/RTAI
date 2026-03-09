"""
core/approval_bridge.py

File-based approval gate between the Fixer Agent and script execution.

After the FixerAgent generates ``Proposed_Fixes.sh``, the SwarmController
sets ``state.awaiting_approval = True`` and sends a Telegram notification.
No scripts are executed until the operator clicks *Approve* in the Streamlit
Dashboard, which calls ``ApprovalBridge.approve()``.

Signal mechanism
----------------
A signal file named ``<engagement>.approved`` is written inside the
engagement's remediation directory when the operator approves.

The helper ``wait_for_approval()`` polls for that file and blocks the calling
thread until it appears (or until the optional timeout expires).

Usage
-----
Dashboard (Streamlit) — when operator clicks Approve::

    from core.approval_bridge import ApprovalBridge
    ApprovalBridge.approve(state.engagement_name, output_dir)

Anywhere that wants to gate on approval::

    from core.approval_bridge import ApprovalBridge
    ApprovalBridge.wait_for_approval(state.engagement_name, output_dir)
    # ... safe to execute fixes now

Non-blocking check::

    if ApprovalBridge.is_approved(state.engagement_name, output_dir):
        ...
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Union


class ApprovalBridge:
    """File-based approval gate for generated remediation scripts."""

    _SIGNAL_SUFFIX = ".approved"

    # ------------------------------------------------------------------
    # Signal file helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _signal_path(engagement: str, output_dir: Union[str, Path]) -> Path:
        """Return the path of the approval signal file."""
        safe = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in engagement
        )
        return Path(output_dir) / f"{safe}{ApprovalBridge._SIGNAL_SUFFIX}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def approve(cls, engagement: str, output_dir: Union[str, Path]) -> Path:
        """
        Write the approval signal file, unblocking any waiting callers.

        Called by the Streamlit Dashboard when the operator clicks *Approve*.

        Parameters
        ----------
        engagement:
            Engagement name (used to derive the signal filename).
        output_dir:
            Path to the engagement's remediation directory
            (e.g. ``remediation/RTAI_Engagement_2026-03-09/``).

        Returns
        -------
        Path of the signal file that was created.
        """
        signal = cls._signal_path(engagement, output_dir)
        signal.parent.mkdir(parents=True, exist_ok=True)
        signal.write_text(
            f"approved\nengagement={engagement}\n",
            encoding="utf-8",
        )
        return signal

    @classmethod
    def revoke(cls, engagement: str, output_dir: Union[str, Path]) -> None:
        """
        Remove the approval signal, re-blocking execution.

        Useful for re-gating after an approved session is rolled back.
        """
        signal = cls._signal_path(engagement, output_dir)
        if signal.exists():
            signal.unlink()

    @classmethod
    def is_approved(cls, engagement: str, output_dir: Union[str, Path]) -> bool:
        """Return True if the operator has approved this engagement's fixes."""
        return cls._signal_path(engagement, output_dir).exists()

    @classmethod
    def wait_for_approval(
        cls,
        engagement: str,
        output_dir: Union[str, Path],
        timeout: float = 0.0,
        poll_interval: float = 2.0,
    ) -> bool:
        """
        Block until the approval signal file appears (or timeout expires).

        This is the execution gate: call it before running
        ``Proposed_Fixes.sh`` to ensure the operator has reviewed and
        approved the generated scripts.

        Parameters
        ----------
        engagement:
            Engagement name.
        output_dir:
            Remediation directory that contains (or will contain) the
            signal file.
        timeout:
            Maximum seconds to wait.  ``0`` (default) means wait forever.
        poll_interval:
            Seconds between file-existence checks (default 2 s).

        Returns
        -------
        ``True`` if approved within the timeout, ``False`` if the timeout
        expired without approval.
        """
        start = time.monotonic()
        while True:
            if cls.is_approved(engagement, output_dir):
                return True
            elapsed = time.monotonic() - start
            if timeout and elapsed >= timeout:
                return False
            time.sleep(poll_interval)

    @classmethod
    def execute_if_approved(
        cls,
        engagement: str,
        output_dir: Union[str, Path],
        bash_path: Union[str, Path],
        args: str = "all",
        dry_run: bool = False,
    ) -> tuple[bool, str]:
        """
        Execute ``Proposed_Fixes.sh`` only if the approval signal is present.

        Parameters
        ----------
        engagement:
            Engagement name (used to locate the signal file).
        output_dir:
            Remediation directory.
        bash_path:
            Absolute path to ``Proposed_Fixes.sh``.
        args:
            Arguments to pass to the script (default ``"all"``).
        dry_run:
            When ``True``, sets ``DRY_RUN=1`` in the environment.

        Returns
        -------
        ``(executed, message)`` — ``executed`` is ``False`` if the gate
        blocked execution; *message* describes the outcome.
        """
        import subprocess

        if not cls.is_approved(engagement, output_dir):
            return (
                False,
                "Execution blocked: fixes have not been approved. "
                "Open the Dashboard and click Approve first.",
            )

        script = Path(bash_path)
        if not script.exists():
            return False, f"Script not found: {script}"

        env_extra = {"DRY_RUN": "1"} if dry_run else {}
        import os
        env = {**os.environ, **env_extra}

        try:
            result = subprocess.run(
                ["bash", str(script), args],
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            output = result.stdout + result.stderr
            if result.returncode == 0:
                return True, output
            return True, f"Script exited with code {result.returncode}:\n{output}"
        except subprocess.TimeoutExpired:
            return True, "Script execution timed out after 600 seconds."
        except Exception as exc:  # noqa: BLE001
            return True, f"Execution error: {exc}"
