from datetime import timedelta

from django.conf import settings as django_settings
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.apps import apps

from auth_token.config import settings
from auth_token.models import Token


class Command(BaseCommand):

    def handle(self, **options):
        for user in apps.get_model(*django_settings.AUTH_USER_MODEL.split('.', 1)).objects.all():
            user_last_preserved_token_pks = Token.objects.filter(
                user=user
            ).order_by('-created_at')[:settings.COUNT_USER_PRESERVED_TOKENS].values_list('pk', flat=True)
            removing_tokens_qs = Token.objects.filter(
                last_access__lt=timezone.now() - timedelta(seconds=settings.MAX_TOKEN_AGE),
                user=user
            ).exclude(pk__in=user_last_preserved_token_pks)
            self.stdout.write('Removing {} tokens of user {}'.format(removing_tokens_qs.count(), user))
            removing_tokens_qs.delete()
