# auth0_talk.py
# Now since auth0_connect.py works, it is now time to talk to the API which will mean using the results from auth0_connect.py to get the access token and then use that access token to talk to the API. This will also get the client_id and other features and integrate with the auth_connect.py This will be done in a new file called auth0_talk.py.
import requests
import json
from auth0_connect import get_access_token

def talk_to_api():
    # Get the access token from auth0_connect.py
    access_token = get_access_token()
    
    # Define the API endpoint you want to talk to
    api_endpoint = "http://localhost:8080/realms/{realm_name}/broker/auth0/endpoint"
    # Set up the headers with the access token
    headers = {headers: {"Authorization": f"Bearer {access_token}"}}
    # Make a GET request to the API endpoint
    response = requests.get(api_endpoint, headers=headers)
    # Check if the request was successful
    if response.status_code == 200:
        print("Successfully talked to the API!")
        print("Response:", response.json())
    else:
        print("Failed to talk to the API. Status code:", response.status_code)
        print("Response:", response.text)
    # Make a SET and a POST request to the API endpoint
    # For example, if you want to create a new user in Keycloak using the API,

    def create_user():
        user_data = {
            "username": "newuser",
            "email": "newemail@example.com",
            "password": "newpassword"
        }
        response = requests.post(api_endpoint, headers=headers, json=user_data)
        if response.status_code == 201:
            print("User created successfully!")
            print("Response:", response.json())
        else:
            print("Failed to create user. Status code:", response.status_code)
            print("Response:", response.text)
        
    # Now have the option to call the create_user function to create a new user in Keycloak using the API
    create_user()
    def update_user():
        user_id = "user_id_to_update"
        user_data = {
            "email": "updatedemail@example.com"
        }
        response = requests.put(f"{api_endpoint}/{user_id}", headers=headers, json=user_data)
        if response.status_code == 200:
            system.out.println("User updated successfully!")
            print("Response:", response.json())
        else:
            print("Failed to update user. Status code:", response.status_code)
            print("Response:", response.text)
    # Now have the option to call the update_user function to update a user in Keycloak
    update_user()
    # Now have the option to call the delete_user function to delete a user in Keycloak
    def delete_user():
        user_id = "user_id_to_delete"
        response = requests.delete(f"{api_endpoint}/{user_id}", headers=headers)
        if response.status_code == 204:
            print("User deleted successfully!")
        else:
            print("Failed to delete user. Status code:", response.status_code)
            print("Response:", response.text)
    delete_user()

    # Do the same thing for the auth0 endpoint
    def talk_to_auth0():
        auth0_api_endpoint = "https://{your_auth0_domain}/api/v2/users"
        response = requests.get(auth0_api_endpoint, headers=headers)
        if response.status_code == 200:
            print("Successfully talked to the Auth0 API!")
            print("Response:", response.json())
        else:
            print("Failed to talk to the Auth0 API. Status code:", response.status_code)
            print("Response:", response.text)

    # Now have the option to call the talk_to_auth0 function to talk to the Auth0 API
    talk_to_auth0()

    # Now have the option to call the create_user function to create a new user in Auth0 using the API
    def create_auth0_user():
        auth0_user_data = {
            "email": "user@example.com"
        }
        response = requests.post(auth0_api_endpoint, headers=headers, json=auth0_user_data)
        if response.status_code == 201:
            print("Auth0 user created successfully!")
            print("Response:", response.json())
        else:
            print("Failed to create Auth0 user. Status code:", response.status_code)
            print("Response:", response.text)
        # Now follow the same process for updating and deleting a user in Auth0 using the API
    def update_auth0_user():
        user_id = "auth0_user_id_to_update"
        auth0_user_data = {
            "email": "updatedemail@example.com"
        }
        response = requests.put(f"{auth0_api_endpoint}/{user_id}", headers=headers, json=auth0_user_data)
        if response.status_code == 200:
            print("Auth0 user updated successfully!")
            print("Response:", response.json())
        else:
            print("Failed to update Auth0 user. Status code:", response.status_code)
            print("Response:", response.text)
    update_auth0_user()
    def delete_auth0_user():
        user_id = "auth0_user_id_to_delete"
        response = requests.delete(f"{auth0_api_endpoint}/{user_id}", headers=headers)
        if response.status_code == 204:
            print("Auth0 user deleted successfully!")
        else:
            print("Failed to delete Auth0 user. Status code:", response.status_code)
            print("Response:", response.text)
    delete_auth0_user()

    # Now have the option to call the create_auth0_user function to create a new user in Auth0 using the API
    create_auth0_user()

if __name__ == "__main__":    
    talk_to_api()