import msal
import requests

from auth_token.config import settings


graph_url = 'https://graph.microsoft.com/v1.0'


def get_user_data(token):
    response = requests.get(
        f'{graph_url}/me',
        headers={'Authorization': f'Bearer {token}'},
        params={'$select': 'displayName,mail,userPrincipalName'}
    )
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_msal_app():
    """
    Initialize the MSAL confidential client
    """
    return msal.PublicClientApplication(
        settings.MS_SSO_APP_ID,
        authority=f'https://login.microsoftonline.com/{settings.MS_SSO_TENANT_ID}'
    )


def get_sign_in_flow():
    """
    Method to generate a sign-in flow
    """
    return get_msal_app().initiate_auth_code_flow(['user.read'])


def acquire_token_by_auth_code_flow(sign_flow, data):
    """
    Method to get auth code from sign flow and request data
    """
    return get_msal_app().acquire_token_by_auth_code_flow(sign_flow, data)
