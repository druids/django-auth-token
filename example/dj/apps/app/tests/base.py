from django.contrib.auth.models import User


class BaseTestCaseMixin:

    def create_user(self):
        return User.objects._create_user('test', 'test@test.cz', 'test', is_staff=True, is_superuser=True)
