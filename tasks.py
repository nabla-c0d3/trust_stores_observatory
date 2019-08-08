from pathlib import Path
from invoke import task

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # Run the test suite
    ctx.run("pytest")

    # Run linters
    ctx.run("flake8 .")
    ctx.run("mypy trust_stores_observatory")
    ctx.run("black -l 120 . --check")
