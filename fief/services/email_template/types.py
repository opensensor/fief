from enum import StrEnum


class EmailTemplateType(StrEnum):
    BASE = "BASE"
    WELCOME = "WELCOME"
    VERIFY_EMAIL = "VERIFY_EMAIL"
    FORGOT_PASSWORD = "FORGOT_PASSWORD"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"

    def get_display_name(self) -> str:
        display_names = {
            EmailTemplateType.BASE: "Base",
            EmailTemplateType.WELCOME: "Welcome",
            EmailTemplateType.VERIFY_EMAIL: "Verify email",
            EmailTemplateType.FORGOT_PASSWORD: "Forgot password",
            EmailTemplateType.MFA_ENABLED: "MFA enabled",
            EmailTemplateType.MFA_DISABLED: "MFA disabled",
        }
        return display_names[self]
