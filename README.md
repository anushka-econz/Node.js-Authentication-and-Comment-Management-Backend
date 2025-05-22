# Node.js Authentication and Comment Management Backend

This backend service provides user authentication (signup, login, logout), authorization using role-based access control (RBAC), session management with JWTs (via cookies), and CRUD operations for comments with fine-grained access control.

## Table of Contents

* [Project Setup](#project-setup)
* [Environment Variables](#environment-variables)
* [Running the Application](#running-the-application)
* [API Endpoints](#api-endpoints)

  * [Root](#root)
  * [Authentication (Users)](#authentication-users)
  * [Comments](#comments)
  * [Test Endpoint](#test-endpoint)
* [Roles and Permissions](#roles-and-permissions)
* [Technologies Used](#technologies-used)

## Project Setup

1. **Clone the repository**

```bash
cd path/to/your/project
```

2. **Install dependencies**

```bash
npm install
```

This will install packages like `express`, `mongoose`, `bcryptjs`, `jsonwebtoken`, `cookie-parser`, `dotenv`, and `validator`.

3. **Install development dependency (optional)**

```bash
npm install --save-dev nodemon
```

## Environment Variables

Create a `.env` file in the root of your project directory.

Example:

```env
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/auth_comments_db_dev
JWT_SECRET=your_super_strong_and_long_jwt_secret_key_please_change_this
JWT_EXPIRES_IN=1h
JWT_COOKIE_EXPIRES_IN=1
```

## Running the Application

For development:

```bash
npm run dev
```

For production:

```bash
npm start
```

Directly with Node:

```bash
node server.js
```

You should see:

```
Server running in development mode on port 5000...
MongoDB Connected Successfully...
```

## API Endpoints

### Root

**GET /**
Check if the API is running.

```json
{
  "status": "success",
  "message": "Welcome to the API! Server is running on port 5000. Environment: development.",
  "documentation_suggestion": "Refer to /api/v1/test or other API endpoints for functionality."
}
```

### Authentication (Users)

#### POST /api/v1/users/signup

Registers a new user.

**Request:**

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password123",
  "role": "user"
}
```

**Response:**

```json
{
  "status": "success",
  "token": "<jwt>",
  "data": {
    "user": {
      "role": "user",
      "_id": "...",
      "username": "...",
      "email": "...",
      "createdAt": "..."
    }
  }
}
```

#### POST /api/v1/users/login

Logs in a user.

**Request:**

```json
{
  "email": "test@example.com",
  "password": "password123"
}
```

#### GET /api/v1/users/logout

Logs out the current user.

**Response:**

```json
{
  "status": "success",
  "message": "Logged out successfully."
}
```

#### PATCH /api/v1/users/\:userId/role (Admin Only)

Updates a user's role.

**Request:**

```json
{
  "role": "moderator"
}
```

## Comments

All comment endpoints require authentication.

### GET /api/v1/comments

Retrieves all comments.

### POST /api/v1/comments

Creates a new comment.

**Request:**

```json
{
  "text": "My new amazing comment!"
}
```

### GET /api/v1/comments/\:id

Retrieves a specific comment by ID.

### PATCH /api/v1/comments/\:id

Updates a comment.

**Request:**

```json
{
  "text": "Updated comment text."
}
```

### DELETE /api/v1/comments/\:id

Deletes a comment.

## Test Endpoint

### GET /api/v1/test

Verifies API routing.

**Response:**

```json
{
  "status": "success",
  "message": "API test endpoint is working!"
}
```

## Roles and Permissions

### User

* Can sign up, log in, log out
* Can create, read, update, delete their own comments

### Moderator

* All User permissions
* Can update and delete any comment

### Admin

* All Moderator permissions
* Can change any user's role

## Technologies Used

* **Node.js**: Runtime environment
* **Express.js**: Web framework
* **MongoDB**: NoSQL database
* **Mongoose**: ODM for MongoDB
* **JWT**: Authentication tokens
* **bcryptjs**: Password hashing
* **cookie-parser**: Cookie parsing
* **dotenv**: Environment configuration
* **validator**: Input validation
