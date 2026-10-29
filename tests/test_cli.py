import pytest
import typer
from pydantic import BaseModel, ValidationError
from typer.testing import CliRunner

from fief.cli import __main__ as cli
from fief.cli.quickstart import add_commands


@pytest.fixture
def command_app():
    app = typer.Typer(cls=cli.CustomUnknownCommandGroup, invoke_without_command=True)

    @app.callback()
    def main():
        pass

    @app.command()
    def quickstart():
        typer.echo("Quickstart is available")

    return app


@pytest.fixture
def invalid_settings(monkeypatch):
    class RequiredSettings(BaseModel):
        secret: str

    with pytest.raises(ValidationError) as exc:
        RequiredSettings.model_validate({})
    monkeypatch.setattr(cli, "settings_validation_errors", exc.value)


def test_missing_settings_are_reported_for_unavailable_commands(
    command_app, invalid_settings
):
    result = CliRunner().invoke(command_app, ["run-server"])
    assert result.exit_code == 1
    assert "Some settings are invalid or missing" in result.output
    assert "secret" in result.output
    assert "No such command" not in result.output


def test_quickstart_is_available_without_settings(command_app, invalid_settings):
    result = CliRunner().invoke(command_app, ["quickstart"])
    assert result.exit_code == 0
    assert "Quickstart is available" in result.output


def test_unknown_command_keeps_standard_error(command_app, monkeypatch):
    monkeypatch.setattr(cli, "settings_validation_errors", None)
    result = CliRunner().invoke(command_app, ["nonexistent"])
    assert result.exit_code == 2
    assert "No such command" in result.output


def test_quickstart_includes_mfa_key_and_fork_image():
    app = add_commands(typer.Typer(invoke_without_command=True))
    result = CliRunner().invoke(
        app,
        [
            "quickstart",
            "--user-email",
            "admin@example.com",
            "--user-password",
            "fief-test-correct-horse-battery-staple",
            "--docker",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "MFA_SECRET_ENCRYPTION_KEY=" in result.output
    assert "ghcr.io/opensensor/fief:latest" in result.output
