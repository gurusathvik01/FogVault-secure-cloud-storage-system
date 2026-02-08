from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from vaultapp.models import SecureFile

class Command(BaseCommand):
    help = "Delete trash files older than 3 days"

    def handle(self, *args, **kwargs):
        expiry = timezone.now() - timedelta(days=3)
        old_files = SecureFile.objects.filter(is_deleted=True, deleted_at__lt=expiry)

        for f in old_files:
            f.file.delete(save=False)
            f.delete()

        self.stdout.write(f"Deleted {old_files.count()} expired trash files")
