"""User and Role ORM models."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from core.storage.models.base import Base
from core.time import utcnow


class User(Base):
    """
    User Model - System users with authentication and authorization.

    Stores user credentials, profile information, and role assignments.
    """

    __tablename__ = "users"

    # Primary key
    user_id: Mapped[str] = mapped_column(String(50), primary_key=True)

    # Authentication
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)

    # Role and permissions
    role_id: Mapped[str] = mapped_column(
        String(50), ForeignKey("roles.role_id"), nullable=False
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mfa_recovery_codes: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )

    # Session tracking
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Failed-login tracking and account lockout
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Password history — list of prior bcrypt hashes, newest first. Used
    # to reject reuse of the last N passwords. Capped in application code.
    password_history: Mapped[List[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default="now()"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default="now()",
    )

    # Indexes
    __table_args__ = (
        Index("idx_user_username", "username"),
        Index("idx_user_email", "email"),
        Index("idx_user_role_id", "role_id"),
        Index("idx_user_is_active", "is_active"),
    )


class Role(Base):
    """
    Role Model - Defines user roles and their permissions.

    RBAC (Role-Based Access Control) system for authorization.
    """

    __tablename__ = "roles"

    # Primary key
    role_id: Mapped[str] = mapped_column(String(50), primary_key=True)

    # Role details
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Permissions (JSONB for flexibility)
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False, default={})

    # System role flag (cannot be deleted/modified)
    is_system_role: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default="now()"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default="now()",
    )

    # Indexes
    __table_args__ = (Index("idx_role_name", "name"),)
