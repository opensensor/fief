from wtforms import HiddenField, validators

from fief.forms import CSRFBaseForm
from fief.locale import gettext_lazy as _


class VerifyEmailForm(CSRFBaseForm):
    code = HiddenField(_("Verification code"), validators=[validators.InputRequired()])

    class Meta:
        id = "verify-email-form"


class VerifyEmailLinkForm(CSRFBaseForm):
    """Confirmation form for the one-click activation link.

    The code travels in a hidden field pre-filled from the link's ``?code=``
    query param; verification only happens when this form is POSTed, so mail
    link scanners (which only GET) cannot consume the one-time code.
    """

    code = HiddenField(_("Verification code"), validators=[validators.InputRequired()])

    class Meta:
        id = "verify-email-link-form"
