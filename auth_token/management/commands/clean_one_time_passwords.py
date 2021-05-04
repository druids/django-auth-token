from datetime import timedelta

from django.db.models import Q
from django.utils import timezone
from django.core.management.base import BaseCommand

from auth_token.config import settings
from auth_token.models import OneTimePassword


class Command(BaseCommand):

    def handle(self, **options):
        inactive_otp_qs = OneTimePassword.objects.filter(
            Q(is_active=False)
            | Q(expires_at__isnull=False, expires_at__lt=timezone.now() - timedelta(
                seconds=settings.OTP_EXPIRATION_RETENTION_PERIOD,
            ))
        )
        self.stdout.write('Will delete {} inactive or expired OTP'.format(
            inactive_otp_qs.count())
        )
        deletion_count = inactive_otp_qs.delete()
        self.stdout.write('Deleted {} inactive or expired OTP'.format(deletion_count[0]))
        self.stdout.write('{} OTP remain in database'.format(OneTimePassword.objects.count()))
