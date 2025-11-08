# sharenv

Shared environment variables, including key rotators

## Usage

To use, add the following to your shell profile (e.g. `~/.bashrc` or `~/.zshrc`):

```sh
export SHARENV_ENDPOINT="https://your-sharenv-endpoint.com/secretapitoken"
eval $(curl -s $SHARENV_ENDPOINT)
```

Then, source your profile or restart your terminal

## Configuration


In the `./vars` directory, create files named after the environment variables you want to set.
If you want to rotate through multiple values for a variable, put them each on their own line in the file.
Changes will be hot-reloaded on change.

