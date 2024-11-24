from pathlib import Path
from invoke import task

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # Run linters
    ctx.run("ruff check")
    ctx.run("mypy trust_stores_observatory")

    # Run the test suite
    ctx.run("pytest")
