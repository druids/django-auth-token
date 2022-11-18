from django.db.models import Count
from django.conf import settings as django_settings
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.apps import apps

from chamber.utils.tqdm import tqdm

from auth_token.config import settings
from auth_token.models import AuthorizationToken


class Command(BaseCommand):

    def handle(self, **options):
        cleaned_users = apps.get_model(*django_settings.AUTH_USER_MODEL.split('.', 1)).objects.annotate(
            count_tokens=Count('authorization_tokens')
        ).filter(count_tokens__gt=settings.COUNT_USER_PRESERVED_TOKENS)

        self.stdout.write('Removing expired tokens')
        for user in tqdm(cleaned_users, file=self.stdout):
            user_last_preserved_token_pks = AuthorizationToken.objects.filter(
                user=user
            ).order_by('-created_at')[:settings.COUNT_USER_PRESERVED_TOKENS].values('pk')
            removing_tokens_qs = AuthorizationToken.objects.filter(
                expires_at__lt=timezone.now(),
                user=user
            ).exclude(pk__in=user_last_preserved_token_pks)
            removing_tokens_qs.delete()
