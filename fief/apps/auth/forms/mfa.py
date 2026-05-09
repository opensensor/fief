from wtforms import PasswordField, StringField, validators

from fief.forms import CSRFBaseForm
from fief.locale import gettext_lazy as _

# Pattern for a 6-digit TOTP code. Stored as text (not int) so leading zeros
# such as "000123" are preserved.
_TOTP_CODE_REGEXP = r"^\d{6}$"

# Pattern for a recovery code, accepting both formatted (XXXX-XXXX) and raw
# (XXXXXXXX) variants. The dash is optional; the alphabet is letters+digits.
_RECOVERY_CODE_REGEXP = r"^[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}$"

# Pattern accepted on the disable form: either a 6-digit TOTP or a recovery
# code (with or without dash).
_TOTP_OR_RECOVERY_CODE_REGEXP = (
    r"^(\d{6}|[A-Za-z0-9]{4}-?[A-Za-z0-9]{4})$"
)


class TotpEnrollConfirmForm(CSRFBaseForm):
    code = StringField(
        _("TOTP code"),
        validators=[
            validators.DataRequired(),
            validators.Regexp(
                _TOTP_CODE_REGEXP,
                message=_(
                    "Enter the 6-digit code from your authenticator."
                ),
            ),
        ],
    )


class TotpVerifyForm(CSRFBaseForm):
    # Same shape as TotpEnrollConfirmForm; reused for the login challenge.
    code = StringField(
        _("TOTP code"),
        validators=[
            validators.DataRequired(),
            validators.Regexp(
                _TOTP_CODE_REGEXP,
                message=_(
                    "Enter the 6-digit code from your authenticator."
                ),
            ),
        ],
    )


class TotpDisableForm(CSRFBaseForm):
    current_password = PasswordField(
        _("Current password"),
        validators=[validators.DataRequired()],
    )
    code = StringField(
        _("TOTP code or recovery code"),
        validators=[
            validators.DataRequired(),
            validators.Regexp(
                _TOTP_OR_RECOVERY_CODE_REGEXP,
                message=_(
                    "Enter your authenticator code or one of your recovery codes."
                ),
            ),
        ],
    )


class MfaRecoveryForm(CSRFBaseForm):
    # Accepts both `xxxx-xxxx` (formatted) and `xxxxxxxx` (raw).
    code = StringField(
        _("Recovery code"),
        validators=[
            validators.DataRequired(),
            validators.Regexp(
                _RECOVERY_CODE_REGEXP,
                message=_("Enter one of your recovery codes."),
            ),
        ],
    )
