from pathlib import Path
from invoke import task, Context

root_path = Path(__file__).parent.absolute()


@task
def test(ctx: Context) -> None:
    # Run linters
    ctx.run("ruff check")
    ctx.run("mypy trust_stores_observatory")

    # Run the test suite
    ctx.run("pytest")


@task
def lint(ctx: Context) -> None:
    ctx.run("ruff format .")
    ctx.run("ruff check . --fix")
    ctx.run("mypy .")
