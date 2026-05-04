import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from scanners.models import ScanJob
from scanners.services import execute_scan_job_pipeline, update_job_progress


class Command(BaseCommand):
    help = "Run the PostgreSQL-backed scan worker using FOR UPDATE SKIP LOCKED."

    def add_arguments(self, parser):
        parser.add_argument("--queue", default=None, help="Optional queue name to limit claims.")
        parser.add_argument("--once", action="store_true", help="Process at most one job and exit.")

    def handle(self, *args, **options):
        poll_seconds = settings.SCAN_QUEUE_POLL_SECONDS
        queue_name = options["queue"]

        while True:
            job = ScanJob.objects.claim_next(queue_name=queue_name)
            if not job:
                if options["once"]:
                    self.stdout.write("No queued jobs available.")
                    return

                time.sleep(poll_seconds)
                continue

            self.stdout.write(f"Claimed job #{job.pk} from queue '{job.queue_name}'.")

            try:
                execute_scan_job_pipeline(job)
                self.stdout.write(self.style.SUCCESS(f"Completed job #{job.pk}."))
            except Exception as exc:
                job.refresh_from_db(fields=["status", "cancellation_requested", "error_logs"])
                if job.status == ScanJob.Status.CANCELLED or job.cancellation_requested:
                    update_job_progress(
                        job,
                        stage=ScanJob.Stage.CANCELLED,
                        status=ScanJob.Status.CANCELLED,
                        clear_current_command=True,
                        ended_at=timezone.now(),
                        message="Job cancelled before the current step completed.",
                        error_logs=job.error_logs or str(exc),
                    )
                    self.stderr.write(self.style.WARNING(f"Job #{job.pk} cancelled."))
                else:
                    update_job_progress(
                        job,
                        stage=ScanJob.Stage.FAILED,
                        status=ScanJob.Status.FAILED,
                        clear_current_command=True,
                        ended_at=timezone.now(),
                        message="Job failed during execution.",
                        error_logs=str(exc),
                    )
                    self.stderr.write(self.style.ERROR(f"Job #{job.pk} failed: {exc}"))

            if options["once"]:
                return