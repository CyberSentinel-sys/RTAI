"""
main.py
CLI entry point for the RTAI autonomous red-team framework.

Runs the full swarm pipeline:
    Scout → Analyst → Strategist → Fixer → Report

The SwarmController activates the Approval Gate after the Fixer Agent
completes and sends a Telegram notification (if configured) before any
remediation script is allowed to execute.

Usage:
    python main.py --target 192.168.1.10 --engagement "Internal_Assessment_Q1"
    sudo python main.py --target 10.0.0.0/24 --engagement "Subnet_Sweep"
"""
import argparse

from agents.swarm_controller import SwarmController


def parse_args() -> argparse.Namespace:
    """Build and parse CLI arguments for the RTAI entry point."""
    parser = argparse.ArgumentParser(
        description="RTAI — Autonomous Multi-Agent Red Team Swarm"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target host / IP / CIDR (must be within authorised scope)"
    )
    parser.add_argument(
        "--engagement", default="",
        help="Human-readable engagement name (used in report filename)"
    )
    return parser.parse_args()


def main() -> None:
    """Run the RTAI pipeline and print the final engagement report to stdout."""
    args = parse_args()
    controller = SwarmController()
    final_state = controller.run(
        target=args.target,
        engagement_name=args.engagement,
    )
    print("\n" + "=" * 60)
    print("ENGAGEMENT COMPLETE")
    print("=" * 60)
    print(final_state.report)
    if final_state.awaiting_approval:
        print("\n[APPROVAL GATE] Review the Battle Plan and remediation scripts,")
        print("then approve via the Streamlit Dashboard before applying fixes.")


if __name__ == "__main__":
    main()
