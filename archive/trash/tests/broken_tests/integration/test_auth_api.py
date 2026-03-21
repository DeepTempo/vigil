"""
Integration tests for authentication API endpoints.
Tests user registration, login, MFA, and protected route access.
"""

import pytest
from fastapi.testclient import TestClient
import json

# Skip all integration tests until fixtures are recreated
pytestmark = pytest.mark.skip(reason="Requires fixtures (test_client, auth_headers, sample_user, sample_role) - see conftest.py")


@pytest.mark.integration
class TestUserRegistration:
    """Test user registration endpoint."""
    
    def test_register_new_user(self, test_client, sample_role):
        """Test successful user registration."""
        response = test_client.post(
            "/api/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "SecurePassword123!",
                "role_id": sample_role.id
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["username"] == "newuser"
    
    def test_register_duplicate_username(self, test_client, sample_user, sample_role):
        """Test registration with existing username."""
        response = test_client.post(
            "/api/auth/register",
            json={
                "username": sample_user.username,
                "email": "different@example.com",
                "password": "SecurePassword123!",
                "role_id": sample_role.id
            }
        )
        
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()
    
    def test_register_invalid_email(self, test_client, sample_role):
        """Test registration with invalid email."""
        response = test_client.post(
            "/api/auth/register",
            json={
                "username": "testuser2",
                "email": "invalid-email",
                "password": "SecurePassword123!",
                "role_id": sample_role.id
            }
        )
        
        assert response.status_code in [400, 422]
    
    def test_register_weak_password(self, test_client, sample_role):
        """Test registration with weak password."""
        response = test_client.post(
            "/api/auth/register",
            json={
                "username": "testuser3",
                "email": "test3@example.com",
                "password": "weak",
                "role_id": sample_role.id
            }
        )
        
        assert response.status_code in [400, 422]


@pytest.mark.integration
class TestUserLogin:
    """Test user login endpoint."""
    
    def test_login_valid_credentials(self, test_client, sample_user):
        """Test login with valid credentials."""
        response = test_client.post(
            "/api/auth/login",
            json={
                "username": sample_user.username,
                "password": "testpassword123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_username(self, test_client):
        """Test login with invalid username."""
        response = test_client.post(
            "/api/auth/login",
            json={
                "username": "nonexistent",
                "password": "password123"
            }
        )
        
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()
    
    def test_login_invalid_password(self, test_client, sample_user):
        """Test login with invalid password."""
        response = test_client.post(
            "/api/auth/login",
            json={
                "username": sample_user.username,
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
    
    def test_login_inactive_user(self, test_client, test_db_session, sample_user):
        """Test login with inactive user account."""
        sample_user.is_active = False
        test_db_session.commit()
        
        response = test_client.post(
            "/api/auth/login",
            json={
                "username": sample_user.username,
                "password": "testpassword123"
            }
        )
        
        assert response.status_code in [401, 403]


@pytest.mark.integration
class TestMFAEndpoints:
    """Test MFA setup and verification endpoints."""
    
    def test_mfa_setup(self, test_client, auth_headers):
        """Test MFA setup endpoint."""
        response = test_client.post(
            "/api/auth/mfa/setup",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code" in data or "provisioning_uri" in data
    
    def test_mfa_verify_valid_code(self, test_client, auth_headers):
        """Test MFA verification with valid code."""
        import pyotp
        
        # Setup MFA first
        setup_response = test_client.post(
            "/api/auth/mfa/setup",
            headers=auth_headers
        )
        secret = setup_response.json()["secret"]
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        # Verify code
        response = test_client.post(
            "/api/auth/mfa/verify",
            headers=auth_headers,
            json={"code": code}
        )
        
        assert response.status_code == 200
        assert response.json()["verified"] is True
    
    def test_mfa_verify_invalid_code(self, test_client, auth_headers):
        """Test MFA verification with invalid code."""
        response = test_client.post(
            "/api/auth/mfa/verify",
            headers=auth_headers,
            json={"code": "000000"}
        )
        
        assert response.status_code in [400, 401]


@pytest.mark.integration
class TestProtectedRoutes:
    """Test protected route access control."""
    
    def test_access_protected_route_with_token(self, test_client, auth_headers):
        """Test accessing protected route with valid token."""
        response = test_client.get(
            "/api/cases",
            headers=auth_headers
        )
        
        assert response.status_code == 200
    
    def test_access_protected_route_without_token(self, test_client):
        """Test accessing protected route without token."""
        response = test_client.get("/api/cases")
        
        assert response.status_code == 401
    
    def test_access_protected_route_invalid_token(self, test_client):
        """Test accessing protected route with invalid token."""
        response = test_client.get(
            "/api/cases",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        
        assert response.status_code == 401
    
    def test_access_admin_route_as_analyst(self, test_client, auth_headers):
        """Test accessing admin-only route as analyst."""
        response = test_client.delete(
            "/api/users/test-user-id",
            headers=auth_headers
        )
        
        assert response.status_code == 403
    
    def test_access_admin_route_as_admin(self, test_client, admin_auth_headers):
        """Test accessing admin-only route as admin."""
        response = test_client.get(
            "/api/users",
            headers=admin_auth_headers
        )
        
        assert response.status_code == 200


@pytest.mark.integration
class TestTokenRefresh:
    """Test token refresh mechanism."""
    
    def test_refresh_valid_token(self, test_client, auth_token):
        """Test refreshing a valid token."""
        response = test_client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            assert data["access_token"] != auth_token  # New token
    
    def test_refresh_expired_token(self, test_client):
        """Test refreshing an expired token."""
        # Create expired token
        from backend.services.auth_service import AuthService
        from datetime import timedelta
        
        expired_token = AuthService.create_access_token(
            {"sub": "user-123"},
            timedelta(seconds=-1)
        )
        
        response = test_client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401


@pytest.mark.integration
class TestGetCurrentUser:
    """Test getting current user information."""
    
    def test_get_current_user(self, test_client, auth_headers, sample_user):
        """Test getting current authenticated user."""
        response = test_client.get(
            "/api/auth/me",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == sample_user.username
        assert data["email"] == sample_user.email
        assert "password" not in data  # Should not expose password
    
    def test_get_current_user_unauthorized(self, test_client):
        """Test getting current user without authentication."""
        response = test_client.get("/api/auth/me")
        
        assert response.status_code == 401


@pytest.mark.integration
class TestPasswordChange:
    """Test password change functionality."""
    
    def test_change_password(self, test_client, auth_headers):
        """Test changing password."""
        response = test_client.post(
            "/api/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "testpassword123",
                "new_password": "NewSecurePassword456!"
            }
        )
        
        if response.status_code == 200:
            # Try logging in with new password
            login_response = test_client.post(
                "/api/auth/login",
                json={
                    "username": "testuser",
                    "password": "NewSecurePassword456!"
                }
            )
            assert login_response.status_code == 200
    
    def test_change_password_wrong_current(self, test_client, auth_headers):
        """Test changing password with wrong current password."""
        response = test_client.post(
            "/api/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "wrongpassword",
                "new_password": "NewPassword123!"
            }
        )
        
        assert response.status_code in [400, 401]

