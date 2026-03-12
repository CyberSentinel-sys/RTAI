"""
main.py
Entry point for the RTAI red-team AI framework.

Usage:
    python main.py --target 192.168.1.10 --engagement "Internal_Assessment_Q1"
"""
import argparse

from core.orchestrator import Orchestrator


def parse_args() -> argparse.Namespace:
    """Build and parse CLI arguments for the RTAI entry point."""
    parser = argparse.ArgumentParser(
        description="RTAI – AI-Driven Red Team Framework"
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
    orchestrator = Orchestrator()
    final_state = orchestrator.run(
        target=args.target,
        engagement_name=args.engagement,
    )
    print("\n" + "=" * 60)
    print("ENGAGEMENT COMPLETE")
    print("=" * 60)
    print(final_state.report)


if __name__ == "__main__":
    main()
