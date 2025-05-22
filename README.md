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

## Screenshots
* **Successful connection**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 25 39 AM" src="https://github.com/user-attachments/assets/de913e69-ba9d-4520-82e5-cf92077c3f86" />
<img width="1512" alt="Screenshot 2025-05-22 at 9 25 42 AM" src="https://github.com/user-attachments/assets/e581be4e-6ab8-47c3-a97a-c4b2525550ba" />

* **User Signup**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 33 22 AM" src="https://github.com/user-attachments/assets/342f06c7-4b11-4308-aa67-42ecb42bcfdd" />

* **Specific Role signup (admin)**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 34 43 AM" src="https://github.com/user-attachments/assets/9aca901d-02d9-4844-ad6c-6086808a4a05" />

* **Login**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 36 56 AM" src="https://github.com/user-attachments/assets/02759833-fed6-4944-bc25-b9d0a1bf90ad" />

* **Adding a new comment**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 39 15 AM" src="https://github.com/user-attachments/assets/bb28cf38-4c65-4622-b459-d10487efbac4" />

* **Viewing all the comments**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 40 14 AM" src="https://github.com/user-attachments/assets/2f35b2ee-2b62-4f95-9d0e-1cb2535784b3" />

* **Editing a comment (as an admin)**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 41 05 AM" src="https://github.com/user-attachments/assets/8e922bed-edbe-408d-9fa2-77f72f840c96" />

* **User Logout**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 41 57 AM" src="https://github.com/user-attachments/assets/bc58734e-d755-4f05-b1a3-020262dcbba1" />

* **Login as a User**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 44 07 AM" src="https://github.com/user-attachments/assets/c365443c-278c-4090-93c2-e5fa67f252b8" />

* **Adding a comment as a User**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 45 07 AM" src="https://github.com/user-attachments/assets/8b50f539-2f39-4929-ba0c-335615a1e055" />

* **Viewing all the comments**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 45 23 AM" src="https://github.com/user-attachments/assets/aeb27eba-0a5b-4839-8bd7-ca0c1edebc31" />

* **Deleting the comment for the signed in user**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 46 02 AM" src="https://github.com/user-attachments/assets/a80593db-b50c-4a72-831f-e9329dbd75ba" />

* **Deleting others comments as a user (fail)**:
<img width="1512" alt="Screenshot 2025-05-22 at 9 51 03 AM" src="https://github.com/user-attachments/assets/f06ed783-db97-4dd1-8c93-528c5fe6a527" />

* **Changing the role of a User (admin)**:
<img width="1512" alt="Screenshot 2025-05-22 at 10 21 13 AM" src="https://github.com/user-attachments/assets/6c690f00-0fb7-4090-becb-b4cee5e2f9e5" />

* **Changing the role of a User (user) : fail**:
<img width="1512" alt="Screenshot 2025-05-22 at 10 22 31 AM" src="https://github.com/user-attachments/assets/c3578344-8e9c-402b-8566-6259aa5debc5" />
