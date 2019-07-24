from django.contrib.auth.models import User


class BaseTestCaseMixin:

    def create_user(self, username='test', email='test@test.cz', password='test'):
        return User.objects._create_user(username, email, password, is_staff=True, is_superuser=True)
