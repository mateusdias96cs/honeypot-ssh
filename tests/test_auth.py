import pytest
import os
import json
from src.core.auth import AuthenticationManager, hash_password

@pytest.fixture
def auth_manager(tmp_path):
    users_file = tmp_path / "users.json"
    
    # Create fake users with plaintext
    users = {
        "testuser": {
            "password": "testpassword",
            "uid": 1000,
            "gid": 1000,
            "shell": "/bin/bash",
            "home": "/home/testuser",
            "real_name": "Test User"
        },
        "hasheduser": {
            "password": hash_password("securepassword"),
            "uid": 1001,
            "gid": 1001,
            "shell": "/bin/bash",
            "home": "/home/hasheduser",
            "real_name": "Hashed User"
        }
    }
    
    with open(users_file, "w") as f:
        json.dump(users, f)
        
    return AuthenticationManager(users_file=str(users_file))

def test_successful_authentication_plaintext_migration(auth_manager):
    # During init, it should have migrated 'testuser' to hash
    success, user_data = auth_manager.authenticate("testuser", "testpassword")
    assert success is True
    assert user_data['uid'] == 1000

    # Ensure it was actually hashed in the file
    with open(auth_manager.users_file, "r") as f:
        users = json.load(f)
        assert users["testuser"]["password"].startswith("$2b$")

def test_successful_authentication_hashed(auth_manager):
    success, user_data = auth_manager.authenticate("hasheduser", "securepassword")
    assert success is True
    assert user_data['uid'] == 1001

def test_failed_authentication_wrong_password(auth_manager):
    success, user_data = auth_manager.authenticate("testuser", "wrongpassword")
    assert success is False
    assert user_data is None

def test_failed_authentication_unknown_user(auth_manager):
    success, user_data = auth_manager.authenticate("unknown", "anypassword")
    assert success is False
    assert user_data is None
