import os

import requests
from dotenv import load_dotenv

load_dotenv()

# ------------------------------------------------------------------------------

class ScanUpdateWebhook():
    def __init__(self):
        # Keycloak url.
        self.access_token_url = os.getenv('toolExecutionStatusKeyCloakURL')
        self.refresh_token = os.getenv('toolExecutionStatusRefreshToken')
        self.client_id = os.getenv('toolExecutionStatusClientID')

        self.access_token = None
        self.access_token = self.get_new_access_token()

    def get_new_access_token(self):
        try:
            if self.access_token != None:
                return self.access_token

            payload = f'refresh_token={self.refresh_token}&grant_type=refresh_token&client_id={self.client_id}'
            response =\
                requests.request(
                    'POST',
                    self.access_token_url,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    data=payload,
                )

            if response.status_code == 200:
                res = response.json()
            
                if 'access_token' in res and len(res['access_token']) > 0:
                    self.access_token = res['access_token']
                    return self.access_token
                else:
                    print('[ - ] Couldn\'t find \'access_token\' property in the keycloak response!')
                    return None
            else:
                print(f'[ - ] Tried to get access token, expected 200 status code, but got status code {response.status_code}!')
                return None
        except Exception as err:
            print(err)
            return None

# ------------------------------------------------------------------------------

wh = ScanUpdateWebhook()
print(wh.access_token)
