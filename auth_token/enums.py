from django.utils.translation import ugettext_lazy as _

from enumfields import Choice, IntegerChoicesEnum


class AuthorizationRequestResult(IntegerChoicesEnum):

    GRANTED = Choice(1, _('granted'))
    DENIED = Choice(2, _('denied'))
    CANCELLED = Choice(3, _('cancelled'))


class AuthorizationRequestState(IntegerChoicesEnum):

    GRANTED = Choice(1, _('granted'))
    DENIED = Choice(2, _('denied'))
    CANCELLED = Choice(3, _('cancelled'))
    WAITING = Choice(4, _('waiting'))
    EXPIRED = Choice(5, _('expired'))
