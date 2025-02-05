"""CMC management command."""

import json
from typing import Any, Literal

from django.core.management import CommandParser
from django.utils import timezone
from django_ca.management.base import BaseCommand
from tabulate import tabulate

from django_ca_cmc.models import CMCClient


class Command(BaseCommand):
    """Command class."""

    help = "List CMC client certificates."

    def add_arguments(self, parser: CommandParser) -> None:
        """Add arguments."""
        parser.add_argument(
            "-f",
            "--format",
            choices=("json", "table"),
            default="table",
            help="Select output format (default: %(default)s).",
        )
        parser.add_argument("-e", "--expired", help="Include clients with expired certificates.")

    def handle(self, format: Literal["json", "table"], expired: bool, **options: Any) -> None:
        """Handle method."""
        clients = CMCClient.objects.all()
        if not expired:
            now = timezone.now()
            clients = clients.filter(not_after__gt=now)

        if format == "json":
            data = [
                {
                    "serial": c.serial,
                    "not_before": c.not_before.isoformat(),
                    "not_after": c.not_after.isoformat(),
                    "comment": c.comment,
                    "pem": c.certificate.pem,
                }
                for c in clients
            ]
            print(json.dumps(data, sort_keys=True, indent=4))
        else:
            headers = ["serial", "not before", "not after", "comment"]
            table = [
                [c.serial, c.not_before.isoformat(), c.not_after.isoformat(), c.comment]
                for c in clients
            ]
            print(tabulate(table, headers, tablefmt="grid"))
