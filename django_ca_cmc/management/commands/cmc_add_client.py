"""CMC management command."""

import os
import sys
from typing import Any

from cryptography import x509
from django.core.management import CommandError, CommandParser
from django_ca.management.base import BaseCommand

from django_ca_cmc.models import CMCClient


class Command(BaseCommand):
    """Command class."""

    help = "Add a CMC client certificate."

    def read_file(self, path: str) -> bytes:
        """Read data from stdin or from a file."""
        if path == "-":
            return sys.stdin.buffer.read()
        if not os.path.exists(path):
            raise CommandError(f"{path}: File does not exist.")
        with open(path, mode="rb") as stream:
            return stream.read()

    def add_arguments(self, parser: CommandParser) -> None:
        """Add arguments."""
        parser.add_argument(
            "-c", "--comment", default="", help="Optional information about this certificate."
        )
        parser.add_argument("certificate", help="Path to the certificate (or - for stdin).")

    def handle(self, certificate: str, comment: str, **options: Any) -> None:
        """Handle method."""
        raw_certificate = self.read_file(certificate)
        try:
            certificate = x509.load_pem_x509_certificate(raw_certificate)
        except ValueError:
            try:
                certificate = x509.load_der_x509_certificate(raw_certificate)
            except ValueError as ex:
                raise CommandError("Cannot parse certificate.") from ex

        client = CMCClient(comment=comment)
        client.update_certificate(certificate)
        client.save()
