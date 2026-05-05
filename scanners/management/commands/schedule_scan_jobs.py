from django.core.management.base import BaseCommand
from django.utils import timezone

from scanners.services import queue_scheduled_scans


class Command(BaseCommand):
    help = "Queue due scheduled scan jobs for installed and active servers."

    def handle(self, *args, **options):
        queued_jobs = queue_scheduled_scans(reference_time=timezone.now())
        if not queued_jobs:
            self.stdout.write("No scheduled scan jobs were due.")
            return

        self.stdout.write(self.style.SUCCESS(f"Queued {len(queued_jobs)} scheduled scan job(s)."))
        for job in queued_jobs:
            self.stdout.write(f"- Job #{job.pk} for {job.server.name} using {job.scan_profile.name if job.scan_profile else 'default profile'}")