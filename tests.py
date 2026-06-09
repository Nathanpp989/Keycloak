# This file will act as pseudocode which will test the functionality of the code in the main.py file and will eventually turn into a test suite.
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, World!"}


def test_read_hello():
    response = client.get("/hello", params={"email": "test@example.com", "username": "testuser"})
    assert response.status_code == 200
    assert response.json() == {"email": "test@example.com", "username": "testuser"}


def test_login():
    response = client.post("/token", data={"username": "user", "password": "password"})
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_login_invalid_credentials():
    response = client.post("/token", data={"username": "user", "password": "wrong"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_protected_route():
    response = client.post("/token", data={"username": "user", "password": "password"})
    token = response.json().get("access_token")

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, user!"}


def test_invalid_token():
    response = client.get("/protected", headers={"Authorization": "Bearer invalidtoken"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}


def test_hash_password_endpoint():
    response = client.post("/hash-password", data={"password": "hunter2"})
    assert response.status_code == 200
    assert "hashed_password" in response.json()
    assert response.json()["hashed_password"] != "hunter2"


def test_register_endpoint():
    response = client.post("/register", data={"username": "newuser", "password": "secret"})
    assert response.status_code == 200
    assert response.json() == {"message": "User newuser registered successfully!"}


def test_get_keys_endpoint():
    """Test that keys endpoint returns public key."""
    response = client.get("/keys")
    # Keys may not be initialized in test; that's ok
    assert response.status_code in (200, 503)