# The goal of this is to connect auth0 to make keycloak "talk", make keycloak point to auth0 as an identity provider, and then use auth0 to talk to the various social providers (google, facebook, etc)
import requests
import json
class Auth0Connect:
    def __init__(self, domain, client_id, client_secret):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = self.get_token()

    def get_token(self):
        url = f"https://{self.domain}/oauth/token"
        headers = {'content-type': 'application/json'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'audience': f"https://{self.domain}/api/v2/",
            'grant_type': 'client_credentials'
        }
        response = requests.post(url, headers=headers, json=data)
        return response.json().get('access_token')

    def create_connection(self, name, strategy):
        url = f"https://{self.domain}/api/v2/connections"
        headers = {
            'content-type': 'application/json',
            'authorization': f"Bearer {self.token}"
        }
        data = {
            "name": name,
            "strategy": strategy
        }
        response = requests.post(url, headers=headers, json=data)
        return response.json()
    
    def create_client(self, name):
        url = f"https://{self.domain}/api/v2/clients"
        headers = {
            'content-type': 'application/json',
            'authorization': f"Bearer {self.token}"
        }
        data = {
            "name": name,
            "app_type": "regular_web",
            "grant_types": ["authorization_code", "refresh_token"],
            "callbacks": ["http://localhost:8080/*"]
        }
        response = requests.post(url, headers=headers, json=data)
        return response.json()
    
# create an access token and use it to call the token access endpoint and ensure that its used to access the api endpoint provided within the code
def test_token_access(auth0):
    token = auth0.get_token()
    print("Access Token:", token)
    url = f"https://{auth0.domain}/api/v2/clients"
    headers = {
        'authorization': f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    print("API Response:", response.json())

    
# Create a signed certificate and use it with traffic corresponding to the traffic setup with ux and show it works with keycloak working with auth0
if __name__ == "__main__":
    domain = "your-auth0-domain"
    client_id = "your-auth0-client-id"
    client_secret = "your-auth0-client-secret"
    auth0 = Auth0Connect(domain, client_id, client_secret)
    connection = auth0.create_connection("keycloak-connection", "auth0")
    print("Connection created:", connection)
    client = auth0.create_client("keycloak-client")
    print("Client created:", client)

# integrate it with the keycloak server by creating a new identity provider in keycloak that points to the auth0 connection created above, and then test the login flow to ensure that users can authenticate using auth0 and access the resources protected by keycloak.
def integrate_with_keycloak(auth0, keycloak_url, realm_name):
    # Create a new identity provider in keycloak that points to the auth0 connection
    url = f"{keycloak_url}/auth/admin/realms/{realm_name}/identity-provider/instances"
    headers = {
        'content-type': 'application/json',
        'authorization': f"Bearer {auth0.token}"
    }
    data = {
        "alias": "auth0",
        "providerId": "oidc",
        "enabled": True,
        "config": {
            "clientId": auth0.client_id,
            "clientSecret": auth0.client_secret,
            "authorizationUrl": f"https://{auth0.domain}/authorize",
            "tokenUrl": f"https://{auth0.domain}/oauth/token",
            "userInfoUrl": f"https://{auth0.domain}/userinfo",
            "jwksUrl": f"https://{auth0.domain}/.well-known/jwks.json"
        }
    }
    response = requests.post(url, headers=headers, json=data)
    print("Identity Provider created:", response.json())

# Make sure it works with the server when it is run with uvicorn and ensure the it works with the traffic setup with the ux and show it works with keycloak working with auth0 by testing the login flow and ensuring that users can authenticate using auth0 and access the resources protected by keycloak.
def test_login_flow(auth0, keycloak_url, realm_name):
    # Simulate a login flow by redirecting the user to the auth0 authorization endpoint and then back to keycloak
    auth_url = f"https://{auth0.domain}/authorize?response_type=code&client_id={auth0.client_id}&redirect_uri=http://localhost:8080/callback&scope=openid profile email"
    print("Redirecting to Auth0 for login:", auth_url)
    # After the user logs in, they will be redirected back to the callback URL with a code, which can be exchanged for tokens
    # This part would typically be handled by your web application, but you can simulate it here for testing purposes
    # For example, you can use a tool like Postman to simulate
    # the redirect and token exchange process, or you can implement a simple web server to handle the callback and token exchange
