# Decap CMS Proxy Server

Decap CMS Proxy Server is an express server created to facilitate local development.

## How It Works

1. Navigate to a local Git repository configured with the CMS.
2. Run `npx decap-cms-server` from the root directory of the above repository.
3. Update your `config.yml` to connect to the server:

```yaml
backend:
  name: proxy
  proxy_url: http://localhost:8081/api/v1
  branch: master # optional, defaults to master
```

4. Start you local development server (e.g. run `gatsby develop`).

## Gene Password

```
npx decap-cms-server --htpasswd admin:1234567
```

## Custom Configuration

1. Create a `.env` file in the root directory of your local Git repository.
2. Update the file as follows:

```bash
NODE_ENV=development
# optional, defaults to current directory
GIT_REPO_DIRECTORY=main
# optional, defaults to 8081
PORT=8082
# optional, defaults to false
LOG_LEVEL=info

HTPASSWD=./.htpasswd
JWT_SECRET="3AB2F6D77A8247A0B1E709847DFD5A76"
PASSWD_SALT="%t#cXfj3@FobPnWM"
```
