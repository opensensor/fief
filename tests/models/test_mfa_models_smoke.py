def test_imports():
    from fief.models import UserMfaRecoveryCode, UserTotpSecret

    # Table prefix (default "fief_") is applied at import time via
    # ``Base.__init_subclass__`` -> ``get_prefixed_tablename``.
    assert UserTotpSecret.__tablename__.endswith("user_totp_secrets")
    assert UserMfaRecoveryCode.__tablename__.endswith("user_mfa_recovery_codes")
