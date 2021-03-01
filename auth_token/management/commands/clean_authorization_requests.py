from datetime import timedelta

from django.utils import timezone
from django.core.management.base import BaseCommand

from auth_token.config import settings
from auth_token.models import AuthorizationRequest


class Command(BaseCommand):

    def handle(self, **options):
        authorization_request_to_delete_qs = AuthorizationRequest.objects.filter(
            expires_at__lt=timezone.now() - timedelta(seconds=settings.AUTHORIZATION_REQUEST_PRESERVE_AGE)
        )
        self.stdout.write('Will delete {} authorization requests'.format(
            authorization_request_to_delete_qs.count())
        )
        deletion_count = authorization_request_to_delete_qs.delete()
        self.stdout.write('Deleted {} authorization requests'.format(deletion_count[0]))
        self.stdout.write('{} authorization requests remain in database'.format(AuthorizationRequest.objects.count()))
