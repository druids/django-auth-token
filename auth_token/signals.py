from collections import defaultdict

from django.dispatch.dispatcher import Signal


class StringSenderSignal(Signal):

    _used_senders = defaultdict(object)

    def _get_unique_sender(self, sender):
        if sender is None:
            return None
        return self._used_senders[sender]

    def connect(self, receiver, sender=None, weak=True, dispatch_uid=None):
        super().connect(receiver, self._get_unique_sender(sender), weak, dispatch_uid)

    def disconnect(self, receiver=None, sender=None, dispatch_uid=None):
        return super().disconnect(receiver, self._get_unique_sender(sender), dispatch_uid)

    def send(self, sender, **named):
        return super().send(self._get_unique_sender(sender), **named)


authorization_granted = StringSenderSignal()
authorization_denied = StringSenderSignal()
authorization_cancelled = StringSenderSignal()
