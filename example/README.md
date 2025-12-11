# passport-local-mongoose Example

This example demonstrates how to use `passport-local-mongoose` with Express and MongoDB to implement username/password authentication.

## What This Example Does

The example sets up a minimal Express application that:

- **Connects to MongoDB** - Uses Mongoose to connect to a local MongoDB instance
- **Configures Passport.js** - Integrates passport-local-mongoose for authentication
- **Provides a login endpoint** - POST `/login-user` to authenticate users with username and password
- **Uses Express sessions** - Manages user sessions after successful authentication

The `passport-local-mongoose` plugin automatically:

- Adds `username`, `hash`, and `salt` fields to the User schema
- Provides `register()`, `authenticate()`, and other authentication methods
- Handles password hashing using PBKDF2
- Integrates with Passport's `LocalStrategy`

## Prerequisites

- **Node.js** (v16 or higher recommended)
- **MongoDB** running locally on `mongodb://127.0.0.1:27017`

## Setup

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Build the main library** (from the root of the repository):

   ```bash
   cd ..
   npm run build
   cd example
   ```

3. **Start MongoDB** (if not already running)

## Running the Example

Start the server:

```bash
npm start
```

The server will start on `http://localhost:3000`.

## Usage

### Register a User

First, you'll need to register a user. You can do this using the `register.js` script:

```bash
node register.js --username <username> --password <password>
```

### Login

Send a POST request to authenticate:

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "password123"}'
```

Successful authentication will create a session and return HTTP 200.
