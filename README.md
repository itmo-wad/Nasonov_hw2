# Login app with Flask

This project demonstrates how to handle user logic in Flask app.

## How to Run
1. Clone the repository.
2. `docker compose up --build --force-recreate`
3. Open your browser and go to `http://127.0.0.1:5000/`.

## What was done

1. Basic part:
    - [x] Listening on localhost:5000
    - [x] Rendering authentication form at http://localhost:5000/login ("/" redirects to login if user not, and to profile if user logged in)
    - [x] Redirecting user to profile page if successfully authenticated
    - [x] Show profile page for authenticated user only at http://localhost:5000/profile
    - [x] User name and password are stored in Mongodb
2. Advanced part:
    - [x] Implemented feature that allows users to create new account, profile will be shown with data respected to each account.
    - [x] Implemented password hashing, logout and password change features
    - [x] Users are allowed to update profile picture (new user will have a default profile picture)
    - [x] Users are allowed to update profile information

When `docker compose down` and then start again, all loaded images will be deleted and users will be displayed with default pictures.
Also, I know that I pushed .env file for repository. It is for demonstration purposes.
