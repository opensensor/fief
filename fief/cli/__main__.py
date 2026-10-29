import typer
import typer.core
from pydantic import ValidationError

from fief.cli.quickstart import add_commands as quickstart_add_commands

settings_validation_errors: ValidationError | None = None


class CustomUnknownCommandGroup(typer.core.TyperGroup):
    def get_command(self, ctx, cmd_name):
        command = super().get_command(ctx, cmd_name)
        if command is None and settings_validation_errors:
            message = typer.style("Some settings are invalid or missing.", fg="red")
            typer.echo(f"{message}\n{settings_validation_errors!s}", err=True)
            raise typer.Exit(code=1) from settings_validation_errors
        return command


app = typer.Typer(
    help="Commands to manage your Fief instance.", cls=CustomUnknownCommandGroup
)
app = quickstart_add_commands(app)

try:
    from fief.cli.admin import add_commands as admin_add_commands

    app = admin_add_commands(app)
except ValidationError as e:
    settings_validation_errors = e

if __name__ == "__main__":
    app()
