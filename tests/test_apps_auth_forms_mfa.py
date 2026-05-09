import pytest
from starlette.datastructures import FormData

from fief.apps.auth.forms.mfa import (
    MfaRecoveryForm,
    TotpDisableForm,
    TotpEnrollConfirmForm,
    TotpVerifyForm,
)


class TestTotpEnrollConfirmForm:
    def test_valid_six_digit_code(self) -> None:
        form = TotpEnrollConfirmForm(
            FormData({"code": "123456"}), meta={"csrf": False}
        )
        assert form.validate() is True
        assert form.code.data == "123456"

    def test_valid_six_digit_code_leading_zeros(self) -> None:
        # StringField (vs IntegerField) preserves leading zeros.
        form = TotpEnrollConfirmForm(
            FormData({"code": "000123"}), meta={"csrf": False}
        )
        assert form.validate() is True
        assert form.code.data == "000123"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "12345",  # too short
            "1234567",  # too long
            "abcdef",  # non-numeric
            "12345a",  # mixed
            "12 345",  # whitespace
        ],
    )
    def test_invalid(self, value: str) -> None:
        form = TotpEnrollConfirmForm(
            FormData({"code": value}), meta={"csrf": False}
        )
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    def test_missing(self) -> None:
        form = TotpEnrollConfirmForm(FormData({}), meta={"csrf": False})
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    def test_has_csrf_token_field(self) -> None:
        # CSRFBaseForm-derived forms get a `csrf_token` field when CSRF is on.
        assert TotpEnrollConfirmForm.Meta.csrf is True
        assert TotpEnrollConfirmForm.Meta.csrf_class is not None


class TestTotpVerifyForm:
    def test_valid_six_digit_code(self) -> None:
        form = TotpVerifyForm(FormData({"code": "654321"}), meta={"csrf": False})
        assert form.validate() is True
        assert form.code.data == "654321"

    def test_valid_six_digit_code_leading_zeros(self) -> None:
        form = TotpVerifyForm(FormData({"code": "000001"}), meta={"csrf": False})
        assert form.validate() is True
        assert form.code.data == "000001"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "12345",
            "1234567",
            "abcdef",
            "abcd-efgh",  # recovery codes are not accepted on the verify form
        ],
    )
    def test_invalid(self, value: str) -> None:
        form = TotpVerifyForm(FormData({"code": value}), meta={"csrf": False})
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    def test_has_csrf_token_field(self) -> None:
        assert TotpVerifyForm.Meta.csrf is True
        assert TotpVerifyForm.Meta.csrf_class is not None


class TestTotpDisableForm:
    def test_valid_with_totp_code(self) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2", "code": "123456"}),
            meta={"csrf": False},
        )
        assert form.validate() is True
        assert form.current_password.data == "hunter2"
        assert form.code.data == "123456"

    def test_valid_with_dashed_recovery_code(self) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2", "code": "abcd-efgh"}),
            meta={"csrf": False},
        )
        assert form.validate() is True
        assert form.code.data == "abcd-efgh"

    def test_valid_with_undashed_recovery_code(self) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2", "code": "ABCDEFGH"}),
            meta={"csrf": False},
        )
        assert form.validate() is True
        assert form.code.data == "ABCDEFGH"

    def test_valid_with_mixed_case_recovery_code(self) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2", "code": "AbCd-1234"}),
            meta={"csrf": False},
        )
        assert form.validate() is True

    def test_missing_password(self) -> None:
        form = TotpDisableForm(
            FormData({"code": "123456"}), meta={"csrf": False}
        )
        assert form.validate() is False
        assert len(form.current_password.errors) >= 1

    def test_missing_code(self) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2"}), meta={"csrf": False}
        )
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    @pytest.mark.parametrize(
        "value",
        [
            "12345",  # not 6 digits and not 8 chars
            "1234567",
            "abcd-efg",  # recovery code wrong length
            "abcdefg",  # 7 chars
            "abc-defgh",  # bad split
            "!!!!-????",  # invalid chars
        ],
    )
    def test_invalid_code_format(self, value: str) -> None:
        form = TotpDisableForm(
            FormData({"current_password": "hunter2", "code": value}),
            meta={"csrf": False},
        )
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    def test_has_csrf_token_field(self) -> None:
        assert TotpDisableForm.Meta.csrf is True
        assert TotpDisableForm.Meta.csrf_class is not None


class TestMfaRecoveryForm:
    @pytest.mark.parametrize(
        "value",
        [
            "abcd-efgh",
            "ABCD-EFGH",
            "abcdefgh",
            "ABCDEFGH",
            "AbCd-1234",
            "1234abcd",
        ],
    )
    def test_valid(self, value: str) -> None:
        form = MfaRecoveryForm(FormData({"code": value}), meta={"csrf": False})
        assert form.validate() is True
        assert form.code.data == value

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "123456",  # 6-digit TOTP code is not a recovery code
            "abcd-efg",  # too short
            "abcdefg",
            "abcd_efgh",  # underscore not allowed
            "abcd--efgh",  # double dash
            "abcd efgh",  # whitespace
            "!!!!????",  # invalid chars
        ],
    )
    def test_invalid(self, value: str) -> None:
        form = MfaRecoveryForm(FormData({"code": value}), meta={"csrf": False})
        assert form.validate() is False
        assert len(form.code.errors) >= 1

    def test_has_csrf_token_field(self) -> None:
        assert MfaRecoveryForm.Meta.csrf is True
        assert MfaRecoveryForm.Meta.csrf_class is not None
