# Example Golang with Cognito authentication

Example code with Cognito

## How to use this code

1. Prepare Cognito client ID and client secret in file named `.env`

    ```bash
    # ./.env
    COGNITO_CLIENT_ID=xxxx
    COGNITO_CLIENT_SECRET=yyyy
    ```

2. Run code with dev mode

    ```bash
    $ go run main.go

    [GIN-debug] [WARNING] Creating an Engine instance with the Logger and Recovery middleware already attached.

    ...
    [GIN-debug] Listening and serving HTTP on :8080
    ```

3. Login with code

    ```bash
    curl -ivL -XPOST http://localhost:8080/user/login \
    -H "Content-Type: application/json" \
    --data '{"username":"user","password":"password"}'
    ```

    ```json
    {
        "access_token":"eyJraWQiOiJjTmhnMEQwTkZ0MHhEMxxxx",
        "id_token":"eyJraWQiOiJXdmRjTG5FaHU4WkVlV2dOWHpxxxx"
    }
    ```
