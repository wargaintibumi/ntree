#!/usr/bin/env python3
"""
NTREE Scheduler
Automated scheduling for recurring penetration tests
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
import schedule
import time

from ntree_agent import NTREEAgent

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.expanduser('~/ntree/logs/ntree_scheduler.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ntree_scheduler')


class NTREEScheduler:
    """
    Scheduler for automated penetration tests.

    Runs NTREE on a schedule (daily, weekly, monthly) for continuous
    security monitoring and testing.
    """

    def __init__(self, config_file: str = "~/ntree/config.json"):
        """
        Initialize scheduler.

        Args:
            config_file: Path to configuration file
        """
        self.config_file = Path(config_file).expanduser()
        self.config = self._load_config()
        self.running = False

        logger.info("NTREE Scheduler initialized")
        logger.info(f"Config: {self.config_file}")

    def _load_config(self) -> Dict:
        """Load configuration from file."""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_file}")

        with open(self.config_file) as f:
            config = json.load(f)

        # Expand paths
        for key in ['home_dir', 'engagements_dir', 'logs_dir', 'templates_dir']:
            if key in config.get('ntree', {}):
                config['ntree'][key] = os.path.expanduser(config['ntree'][key])

        return config

    async def run_scheduled_pentest(self):
        """Run a scheduled penetration test."""
        logger.info("=" * 80)
        logger.info("SCHEDULED PENETRATION TEST STARTING")
        logger.info(f"Time: {datetime.now().isoformat()}")
        logger.info("=" * 80)

        try:
            automation_config = self.config.get('automation', {})

            scope_file = os.path.expanduser(automation_config.get('scope_file', ''))
            roe_file = os.path.expanduser(automation_config.get('roe_file', ''))

            if not scope_file or not Path(scope_file).exists():
                logger.error(f"Scope file not found: {scope_file}")
                return

            # Initialize agent
            api_key = self.config['anthropic']['api_key']
            agent = NTREEAgent(api_key=api_key)

            # Run pentest
            max_iterations = self.config.get('pentest', {}).get('max_iterations', 50)

            summary = await agent.run_autonomous_pentest(
                scope_file=scope_file,
                roe_file=roe_file,
                max_iterations=max_iterations
            )

            logger.info("Scheduled pentest completed successfully")
            logger.info(f"Summary: {json.dumps(summary, indent=2)}")

            # Send notifications
            await self._send_notification(summary)

        except Exception as e:
            logger.error(f"Scheduled pentest failed: {e}", exc_info=True)
            await self._send_error_notification(str(e))

    async def _send_notification(self, summary: Dict):
        """Send completion notification."""
        automation_config = self.config.get('automation', {})

        # Email notification
        email = automation_config.get('notification_email')
        if email:
            logger.info(f"Sending email notification to {email}")
            # TODO: Implement email sending
            pass

        # Webhook notification
        webhook = automation_config.get('notification_webhook')
        if webhook:
            logger.info(f"Sending webhook notification to {webhook}")
            import requests
            try:
                requests.post(webhook, json={
                    'type': 'pentest_complete',
                    'summary': summary,
                    'timestamp': datetime.now().isoformat()
                }, timeout=10)
            except Exception as e:
                logger.error(f"Webhook notification failed: {e}")

    async def _send_error_notification(self, error: str):
        """Send error notification."""
        automation_config = self.config.get('automation', {})

        webhook = automation_config.get('notification_webhook')
        if webhook:
            import requests
            try:
                requests.post(webhook, json={
                    'type': 'pentest_error',
                    'error': error,
                    'timestamp': datetime.now().isoformat()
                }, timeout=10)
            except Exception as e:
                logger.error(f"Error webhook notification failed: {e}")

    def start(self):
        """Start the scheduler."""
        if not self.config.get('automation', {}).get('enabled', False):
            logger.warning("Automation is disabled in config")
            return

        # Parse schedule
        cron_schedule = self.config.get('automation', {}).get('schedule', '0 2 * * 0')
        logger.info(f"Schedule: {cron_schedule}")

        # Convert cron to schedule library format
        # Example: "0 2 * * 0" = Every Sunday at 2:00 AM
        parts = cron_schedule.split()
        if len(parts) == 5:
            minute, hour, day_month, month, day_week = parts

            # Simple scheduling (weekly example)
            if day_week != '*':
                days_map = {'0': 'sunday', '1': 'monday', '2': 'tuesday',
                           '3': 'wednesday', '4': 'thursday', '5': 'friday',
                           '6': 'saturday'}

                if day_week in days_map:
                    day_name = days_map[day_week]
                    time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"

                    # Schedule the job
                    getattr(schedule.every(), day_name).at(time_str).do(
                        lambda: asyncio.run(self.run_scheduled_pentest())
                    )
                    logger.info(f"Scheduled: Every {day_name} at {time_str}")

            # Daily scheduling
            elif day_week == '*' and day_month == '*':
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"
                schedule.every().day.at(time_str).do(
                    lambda: asyncio.run(self.run_scheduled_pentest())
                )
                logger.info(f"Scheduled: Every day at {time_str}")

        logger.info("Scheduler started. Press Ctrl+C to stop.")
        self.running = True

        try:
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
            self.running = False

    def stop(self):
        """Stop the scheduler."""
        logger.info("Stopping scheduler...")
        self.running = False


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="NTREE Scheduler for Automated Pentests")
    parser.add_argument("--config", default="~/ntree/config.json",
                       help="Path to configuration file")
    parser.add_argument("--once", action="store_true",
                       help="Run once immediately instead of scheduling")

    args = parser.parse_args()

    try:
        scheduler = NTREEScheduler(config_file=args.config)

        if args.once:
            # Run immediately
            logger.info("Running pentest immediately (--once mode)")
            asyncio.run(scheduler.run_scheduled_pentest())
        else:
            # Start scheduler
            scheduler.start()

        return 0

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
