.. _commands:

Commands
========

clean_authorization_tokens
--------------------------

Command removes expired tokens of all users. Setting ``AUTH_TOKEN_COUNT_USER_PRESERVED_TOKENS`` defines number of expired tokens that will be preserved per user.

clean_one_time_passwords
------------------------

Command removes expired on inactive one time passwords from database.

clean_authorization_requests
----------------------------

Command removes authorization requests which was expired longer than ``AUTH_TOKEN_AUTHORIZATION_REQUEST_PRESERVE_AGE``. Default value is 7 days therefore authorization requests which were expired more than 7 days will be removed.