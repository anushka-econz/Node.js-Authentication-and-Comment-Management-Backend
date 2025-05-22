// Server.js - Main application file
// This is the entry point of your Node.js application.

//-------------------------------------------------------------------
// 1. FILE: .env (Create this file in the root of your project)
//-------------------------------------------------------------------
/*
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/auth_comments_db_prod
# For development, you might use: MONGO_URI=mongodb://localhost:27017/auth_comments_db_dev
JWT_SECRET=a_very_strong_and_long_secret_key_for_jwt
JWT_EXPIRES_IN=1h
JWT_COOKIE_EXPIRES_IN=1 # in days, for cookie expiration
*/

//-------------------------------------------------------------------
// 2. FILE: package.json (Run `npm init -y` then `npm install express mongoose bcryptjs jsonwebtoken cookie-parser dotenv validator` )
//-------------------------------------------------------------------
/*
{
  "name": "nodejs-auth-comments-backend",
  "version": "1.0.0",
  "description": "Backend service for user authentication, authorization, and comment management.",
  "main": "server.js",
  "scripts": {
    "start": "NODE_ENV=production node server.js",
    "dev": "nodemon server.js"
  },
  "keywords": ["nodejs", "express", "mongodb", "authentication", "authorization", "jwt"],
  "author": "Your Name",
  "license": "ISC",
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.0.0",
    "validator": "^13.9.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.20"
  }
}
*/

//-------------------------------------------------------------------
// 3. FILE: utils/AppError.js
//-------------------------------------------------------------------
// Path: utils/AppError.js
class AppError extends Error {
  constructor(message, statusCode) {
    super(message); // Call the parent constructor (Error)

    this.statusCode = statusCode;
    // Determine status based on statusCode (4xx for 'fail', 5xx for 'error')
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    // Operational errors are trusted errors that we expect (e.g., user input error)
    this.isOperational = true;

    // Capture the stack trace, excluding the constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
}
// module.exports = AppError; // We will define it in server.js for simplicity in this single file format

//-------------------------------------------------------------------
// 4. FILE: config/db.js
//-------------------------------------------------------------------
// Path: config/db.js
const mongooseConfig = require("mongoose"); // Renamed to avoid conflict
const dotenvConfigDb = require("dotenv"); // Renamed to avoid conflict

dotenvConfigDb.config(); // Load environment variables

const connectDB = async () => {
  try {
    await mongooseConfig.connect(process.env.MONGO_URI, {
      // useNewUrlParser: true, // No longer needed in Mongoose 6+
      // useUnifiedTopology: true, // No longer needed
      // useCreateIndex: true, // No longer needed (Mongoose handles this internally)
      // useFindAndModify: false // No longer needed
    });
    console.log("MongoDB Connected Successfully...");
  } catch (err) {
    console.error("MongoDB Connection Error:", err.message);
    // Exit process with failure
    process.exit(1);
  }
};
// module.exports = connectDB; // We will define it in server.js

//-------------------------------------------------------------------
// 5. FILE: models/User.js
//-------------------------------------------------------------------
// Path: models/User.js
const mongooseUser = require("mongoose"); // Renamed
const bcryptUser = require("bcryptjs"); // Renamed
const validatorUser = require("validator"); // Renamed

const userSchema = new mongooseUser.Schema({
  username: {
    type: String,
    required: [true, "Username is required."],
    unique: true,
    trim: true,
    minlength: [3, "Username must be at least 3 characters long."],
    maxlength: [30, "Username cannot exceed 30 characters."],
  },
  email: {
    type: String,
    required: [true, "Email is required."],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validatorUser.isEmail, "Please provide a valid email address."],
  },
  password: {
    type: String,
    required: [true, "Password is required."],
    minlength: [8, "Password must be at least 8 characters long."],
    select: false, // Do not send password back in queries by default
  },
  role: {
    type: String,
    enum: ["user", "moderator", "admin"],
    default: "user",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  // You might add fields like passwordChangedAt, passwordResetToken, passwordResetExpires
});

// Middleware to hash password before saving (if modified)
userSchema.pre("save", async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified("password")) return next();

  // Hash the password with cost of 12
  this.password = await bcryptUser.hash(this.password, 12);
  next();
});

// Instance method to compare candidate password with user's hashed password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcryptUser.compare(candidatePassword, userPassword);
};

// const User = mongooseUser.model('User', userSchema);
// module.exports = User; // We will define it in server.js

//-------------------------------------------------------------------
// 6. FILE: models/Comment.js
//-------------------------------------------------------------------
// Path: models/Comment.js
const mongooseComment = require("mongoose"); // Renamed

const commentSchema = new mongooseComment.Schema({
  text: {
    type: String,
    required: [true, "Comment text cannot be empty."],
    trim: true,
    maxlength: [1000, "Comment cannot exceed 1000 characters."],
  },
  author: {
    type: mongooseComment.Schema.Types.ObjectId,
    ref: "User", // Reference to the User model
    required: [true, "Comment must have an author."],
  },
  // Example: If comments are related to a post/article
  // postId: {
  //   type: mongooseComment.Schema.Types.ObjectId,
  //   ref: 'Post', // Reference to a Post model (if you have one)
  //   required: [true, 'Comment must belong to a post.']
  // },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Middleware to update 'updatedAt' field on save/update
commentSchema.pre("save", function (next) {
  if (this.isModified() && !this.isNew) {
    // Check if document is modified and not new
    this.updatedAt = Date.now();
  }
  next();
});

// If you use findOneAndUpdate, this middleware won't run by default.
// You might need to handle updatedAt in the controller or use a different hook.
// For findByIdAndUpdate, you can set { new: true, runValidators: true, timestamps: { updatedAt: true } }

// const Comment = mongooseComment.model('Comment', commentSchema);
// module.exports = Comment; // We will define it in server.js

//-------------------------------------------------------------------
// 7. FILE: controllers/authController.js
//-------------------------------------------------------------------
// Path: controllers/authController.js
const jwtAuthController = require("jsonwebtoken"); // Renamed
// const UserAuthController = require('../models/User'); // Defined below
// const AppErrorAuthController = require('../utils/AppError'); // Defined below
const { promisify: promisifyAuthController } = require("util"); // Renamed

const signToken = (id) => {
  return jwtAuthController.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() +
        parseInt(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000 // e.g., 1 day
    ),
    httpOnly: true, // Cookie cannot be accessed or modified by the browser
    secure: req.secure || req.headers["x-forwarded-proto"] === "https", // Send only on HTTPS
  };

  res.cookie("jwt", token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

// exports.signup = async (req, res, next) => { ... } // Defined below with access to User and AppError

// exports.login = async (req, res, next) => { ... } // Defined below

// exports.logout = (req, res) => { ... } // Defined below

// exports.protect = async (req, res, next) => { ... } // This is authMiddleware, moved to its section

// exports.restrictTo = (...roles) => { ... } // This is permissionsMiddleware, moved to its section

//-------------------------------------------------------------------
// 8. FILE: middleware/authMiddleware.js
//-------------------------------------------------------------------
// Path: middleware/authMiddleware.js
const jwtAuthMiddleware = require("jsonwebtoken"); // Renamed
// const UserAuthMiddleware = require('../models/User'); // Defined below
// const AppErrorAuthMiddleware = require('../utils/AppError'); // Defined below
const { promisify: promisifyAuthMiddleware } = require("util"); // Renamed

// exports.protect = async (req, res, next) => { ... } // Defined below with access to User and AppError

//-------------------------------------------------------------------
// 9. FILE: middleware/permissionsMiddleware.js
//-------------------------------------------------------------------
// Path: middleware/permissionsMiddleware.js
// const AppErrorPermissionsMiddleware = require('../utils/AppError'); // Defined below
// const CommentPermissionsMiddleware = require('../models/Comment'); // Defined below

// exports.restrictTo = (...roles) => { ... } // Defined below

// exports.canManageComment = async (req, res, next) => { ... } // Defined below

//-------------------------------------------------------------------
// 10. FILE: controllers/commentController.js
//-------------------------------------------------------------------
// Path: controllers/commentController.js
// const CommentCommentController = require('../models/Comment'); // Defined below
// const AppErrorCommentController = require('../utils/AppError'); // Defined below

// exports.getAllComments = async (req, res, next) => { ... } // Defined below
// exports.getComment = async (req, res, next) => { ... } // Defined below
// exports.createComment = async (req, res, next) => { ... } // Defined below
// exports.updateComment = async (req, res, next) => { ... } // Defined below
// exports.deleteComment = async (req, res, next) => { ... } // Defined below

//-------------------------------------------------------------------
// 11. FILE: routes/authRoutes.js
//-------------------------------------------------------------------
// Path: routes/authRoutes.js
const expressAuthRoutes = require("express"); // Renamed
// const authControllerAuthRoutes = require('../controllers/authController'); // Defined below

const authRouter = expressAuthRoutes.Router();

// authRouter.post('/signup', authControllerAuthRoutes.signup); // Will be attached later
// authRouter.post('/login', authControllerAuthRoutes.login);
// authRouter.get('/logout', authControllerAuthRoutes.logout); // GET for simplicity, POST is also fine

// module.exports = authRouter; // Defined in server.js

//-------------------------------------------------------------------
// 12. FILE: routes/commentRoutes.js
//-------------------------------------------------------------------
// Path: routes/commentRoutes.js
const expressCommentRoutes = require("express"); // Renamed
// const commentControllerCommentRoutes = require('../controllers/commentController'); // Defined below
// const authMiddlewareCommentRoutes = require('../middleware/authMiddleware'); // Defined below
// const permissionsMiddlewareCommentRoutes = require('../middleware/permissionsMiddleware'); // Defined below

const commentRouter = expressCommentRoutes.Router();

// // Protect all routes after this middleware
// commentRouter.use(authMiddlewareCommentRoutes.protect);

// commentRouter
//     .route('/')
//     .get(commentControllerCommentRoutes.getAllComments)
//     .post(
//         permissionsMiddlewareCommentRoutes.restrictTo('user', 'moderator', 'admin'), // Only these roles can create
//         commentControllerCommentRoutes.createComment
//     );

// commentRouter
//     .route('/:id')
//     .get(commentControllerCommentRoutes.getComment) // Any authenticated user can read
//     .patch( // Using PATCH for partial updates, PUT for full replacement
//         permissionsMiddlewareCommentRoutes.canManageComment, // Custom logic for comment update
//         commentControllerCommentRoutes.updateComment
//     )
//     .delete(
//         permissionsMiddlewareCommentRoutes.canManageComment, // Custom logic for comment delete
//         commentControllerCommentRoutes.deleteComment
//     );

// module.exports = commentRouter; // Defined in server.js

//-------------------------------------------------------------------
// SERVER.JS - Main Application File (Continues here)
//-------------------------------------------------------------------
const express = require("express");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const path = require("path"); // For potential future static file serving

// Load environment variables
dotenv.config(); // Ensure this is at the top

// --- Define classes and models directly for single-file structure ---
// AppError (from utils/AppError.js)
class AppErrorDef extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}
//const AppError = AppErrorDef; // Use this name consistently

// User Model (from models/User.js)
const mongooseForUser = require("mongoose");
const bcryptForUser = require("bcryptjs");
const validatorForUser = require("validator");

const userSchemaDef = new mongooseForUser.Schema({
  username: {
    type: String,
    required: [true, "Username is required."],
    unique: true,
    trim: true,
    minlength: [3, "Username must be at least 3 characters long."],
    maxlength: [30, "Username cannot exceed 30 characters."],
  },
  email: {
    type: String,
    required: [true, "Email is required."],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [
      validatorForUser.isEmail,
      "Please provide a valid email address.",
    ],
  },
  password: {
    type: String,
    required: [true, "Password is required."],
    minlength: [8, "Password must be at least 8 characters long."],
    select: false,
  },
  role: { type: String, enum: ["user", "moderator", "admin"], default: "user" },
  createdAt: { type: Date, default: Date.now },
});
userSchemaDef.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcryptForUser.hash(this.password, 12);
  next();
});
userSchemaDef.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcryptForUser.compare(candidatePassword, userPassword);
};
const User = mongooseForUser.model("User", userSchemaDef);

// Comment Model (from models/Comment.js)
const mongooseForComment = require("mongoose");
const commentSchemaDef = new mongooseForComment.Schema({
  text: {
    type: String,
    required: [true, "Comment text cannot be empty."],
    trim: true,
    maxlength: [1000, "Comment cannot exceed 1000 characters."],
  },
  author: {
    type: mongooseForComment.Schema.Types.ObjectId,
    ref: "User",
    required: [true, "Comment must have an author."],
  },
  // postId: { type: mongooseForComment.Schema.Types.ObjectId, ref: 'Post', required: [true, 'Comment must belong to a post.']},
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
commentSchemaDef.pre("save", function (next) {
  if (this.isModified() && !this.isNew) {
    this.updatedAt = Date.now();
  }
  next();
});
const Comment = mongooseForComment.model("Comment", commentSchemaDef);

// --- Auth Controller (from controllers/authController.js) ---
const jwtForAuthController = require("jsonwebtoken");
const { promisify: promisifyForAuthController } = require("util");

const authController = {};

authController.signToken = (id) => {
  return jwtForAuthController.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

authController.createSendToken = (user, statusCode, req, res) => {
  const token = authController.signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() +
        parseInt(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  };
  res.cookie("jwt", token, cookieOptions);
  user.password = undefined;
  res.status(statusCode).json({ status: "success", token, data: { user } });
};

authController.signup = async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;
    // Basic validation, Mongoose schema handles more
    if (!username || !email || !password) {
      return next(
        new AppError("Please provide username, email, and password!", 400)
      );
    }

    const newUser = await User.create({
      username,
      email,
      password,
      role: role && ["admin", "moderator"].includes(role) ? role : "user", // Allow role setting, default to user
    });
    authController.createSendToken(newUser, 201, req, res);
  } catch (err) {
    if (err.code === 11000) {
      // Duplicate key error
      return next(
        new AppError(
          `Duplicate field value: ${Object.keys(
            err.keyValue
          )}. Please use another value.`,
          400
        )
      );
    }
    if (err.name === "ValidationError") {
      const errors = Object.values(err.errors).map((el) => el.message);
      const message = `Invalid input data. ${errors.join(". ")}`;
      return next(new AppError(message, 400));
    }
    next(err); // Pass other errors to global error handler
  }
};

authController.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return next(new AppError("Please provide email and password!", 400));
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError("Incorrect email or password.", 401));
    }
    authController.createSendToken(user, 200, req, res);
  } catch (err) {
    next(err);
  }
};

authController.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000), // Expires in 10 seconds
    httpOnly: true,
  });
  res
    .status(200)
    .json({ status: "success", message: "Logged out successfully." });
};

// NEW CONTROLLER FUNCTION FOR ADMIN TO UPDATE USER ROLE
authController.updateUserRoleByAdmin = async (req, res, next) => {
  try {
    const { role } = req.body;
    const userIdToUpdate = req.params.userId;

    // Validate the role input
    if (!role || !["user", "moderator", "admin"].includes(role)) {
      return next(
        new AppError(
          "Invalid role specified. Allowed roles are: user, moderator, admin.",
          400
        )
      );
    }

    // Optional: Prevent an admin from changing their own role if it's a demotion,
    // or from changing the role of the very last admin to a non-admin role.
    // This logic can be complex and depends on application requirements.
    // For instance, to prevent an admin from accidentally demoting themselves:
    // if (req.user.id === userIdToUpdate && req.user.role === 'admin' && role !== 'admin') {
    //     return next(new AppError('Admins cannot demote themselves via this endpoint.', 403));
    // }

    const updatedUser = await User.findByIdAndUpdate(
      userIdToUpdate,
      { role }, // Only update the role
      {
        new: true, // Return the modified document
        runValidators: true, // Run schema validators (e.g., enum validation for role)
      }
    );

    if (!updatedUser) {
      return next(new AppError("No user found with that ID to update.", 404));
    }

    // Password is not selected by default due to `select: false` in schema,
    // so no need to explicitly remove it from `updatedUser` here.

    res.status(200).json({
      status: "success",
      data: {
        user: updatedUser, // Send back the updated user object (without password)
      },
    });
  } catch (err) {
    // Handle potential errors, e.g., validation error if role is not in enum from runValidators
    if (err.name === "ValidationError") {
      const errors = Object.values(err.errors).map((el) => el.message);
      const message = `Invalid input data. ${errors.join(". ")}`;
      return next(new AppError(message, 400));
    }
    next(err); // Pass other errors to the global error handler
  }
};

// --- Auth Middleware (from middleware/authMiddleware.js) ---
const jwtForAuthMiddleware = require("jsonwebtoken");
const { promisify: promisifyForAuthMiddleware } = require("util");
const authMiddleware = {};

authMiddleware.protect = async (req, res, next) => {
  try {
    let token;
    // 1) Get token from header or cookie
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (
      req.cookies &&
      req.cookies.jwt &&
      req.cookies.jwt !== "loggedout"
    ) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(
        new AppError("You are not logged in. Please log in to get access.", 401)
      );
    }

    // 2) Verify token
    const decoded = await promisifyForAuthMiddleware(
      jwtForAuthMiddleware.verify
    )(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError("The user belonging to this token no longer exists.", 401)
      );
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser; // Attach user to request object for subsequent middleware/controllers
    next();
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return next(new AppError("Invalid token. Please log in again.", 401));
    }
    if (err.name === "TokenExpiredError") {
      return next(
        new AppError("Your token has expired. Please log in again.", 401)
      );
    }
    next(new AppError("Authentication failed. Please log in.", 401)); // Generic auth error
  }
};

// --- Permissions Middleware (from middleware/permissionsMiddleware.js) ---
const permissionsMiddleware = {};

permissionsMiddleware.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array like ['admin', 'moderator']
    // req.user is available from the 'protect' middleware
    if (!req.user || !roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action.", 403)
      ); // 403 Forbidden
    }
    next();
  };
};

permissionsMiddleware.canManageComment = async (req, res, next) => {
  try {
    const commentId = req.params.id;
    const comment = await Comment.findById(commentId);

    if (!comment) {
      return next(new AppError("Comment not found.", 404));
    }

    const user = req.user; // From protect middleware

    // Admins can do anything
    if (user.role === "admin") {
      return next();
    }

    // Moderators can manage (update/delete) any comment
    if (
      user.role === "moderator" &&
      (req.method === "PATCH" || req.method === "DELETE")
    ) {
      return next();
    }

    // Users can manage (update/delete) their own comments
    if (comment.author.toString() === user._id.toString()) {
      if (req.method === "PATCH" || req.method === "DELETE") {
        return next();
      }
    }

    // Allow reading for any authenticated user (if GET request reaches here after protect)
    if (req.method === "GET") {
      return next();
    }

    return next(
      new AppError(
        "You do not have permission to perform this action on this comment.",
        403
      )
    );
  } catch (err) {
    next(err);
  }
};

// --- Comment Controller (from controllers/commentController.js) ---
const commentController = {};

commentController.getAllComments = async (req, res, next) => {
  try {
    // Add filtering or pagination as needed
    // Example: const comments = await Comment.find({ postId: req.query.postId }).populate('author', 'username');
    const comments = await Comment.find().populate(
      "author",
      "username email role"
    ); // Populate author details
    res.status(200).json({
      status: "success",
      results: comments.length,
      data: { comments },
    });
  } catch (err) {
    next(err);
  }
};

commentController.getComment = async (req, res, next) => {
  try {
    const comment = await Comment.findById(req.params.id).populate(
      "author",
      "username email role"
    );
    if (!comment) {
      return next(new AppError("No comment found with that ID.", 404));
    }
    res.status(200).json({
      status: "success",
      data: { comment },
    });
  } catch (err) {
    next(err);
  }
};

commentController.createComment = async (req, res, next) => {
  try {
    const { text /*, postId */ } = req.body; // Assuming postId is sent if comments are linked to posts
    const author = req.user._id; // From protect middleware

    if (!text) {
      return next(new AppError("Comment text cannot be empty.", 400));
    }

    const newComment = await Comment.create({ text, author /*, postId */ });
    // Populate author info for the response
    await newComment.populate("author", "username email role");

    res.status(201).json({
      status: "success",
      data: { comment: newComment },
    });
  } catch (err) {
    if (err.name === "ValidationError") {
      const errors = Object.values(err.errors).map((el) => el.message);
      const message = `Invalid input data. ${errors.join(". ")}`;
      return next(new AppError(message, 400));
    }
    next(err);
  }
};

commentController.updateComment = async (req, res, next) => {
  try {
    const { text } = req.body;
    if (!text) {
      return next(
        new AppError("Comment text cannot be empty for an update.", 400)
      );
    }
    // findByIdAndUpdate will not run 'save' middleware by default for 'updatedAt'
    // So, we set it manually or use { new: true, runValidators: true, timestamps: { updatedAt: true } } if Mongoose supports it this way.
    // Simpler to set it manually here:
    const updatedComment = await Comment.findByIdAndUpdate(
      req.params.id,
      { text, updatedAt: Date.now() },
      { new: true, runValidators: true } // Return the modified document and run schema validators
    ).populate("author", "username email role");

    if (!updatedComment) {
      return next(
        new AppError("No comment found with that ID to update.", 404)
      );
    }

    res.status(200).json({
      status: "success",
      data: { comment: updatedComment },
    });
  } catch (err) {
    if (err.name === "ValidationError") {
      const errors = Object.values(err.errors).map((el) => el.message);
      const message = `Invalid input data. ${errors.join(". ")}`;
      return next(new AppError(message, 400));
    }
    next(err);
  }
};

commentController.deleteComment = async (req, res, next) => {
  try {
    const comment = await Comment.findByIdAndDelete(req.params.id);
    if (!comment) {
      return next(
        new AppError("No comment found with that ID to delete.", 404)
      );
    }
    res.status(204).json({
      // 204 No Content
      status: "success",
      data: null,
    });
  } catch (err) {
    next(err);
  }
};

// --- Initialize Express App ---
const app = express();

// --- Database Connection ---
// connectDB(); // Call the function from config/db.js (defined above)
(async () => {
  try {
    await mongooseConfig.connect(process.env.MONGO_URI);
    console.log("MongoDB Connected Successfully (within server.js)...");
  } catch (err) {
    console.error("MongoDB Connection Error (within server.js):", err.message);
    process.exit(1);
  }
})();

// --- Middlewares ---
// Body parser, reading data from body into req.body
app.use(express.json({ limit: "10kb" })); // Limit request body size
app.use(express.urlencoded({ extended: true, limit: "10kb" })); // For form data

// Cookie parser
app.use(cookieParser());

// Data sanitization against NoSQL query injection (can add 'express-mongo-sanitize')
// Data sanitization against XSS (can add 'xss-clean')
// Prevent parameter pollution (can add 'hpp')

// --- Routes ---
// Root route handler
app.get("/", (req, res) => {
  const port = process.env.PORT || 3000; // Get the configured port
  res.status(200).json({
    status: "success",
    message: `Welcome to the API! Server is running on port ${port}. Environment: ${process.env.NODE_ENV}.`,
    documentation_suggestion:
      "Refer to /api/v1/test or other API endpoints for functionality.",
  });
});

// Auth Routes (from routes/authRoutes.js)
const mainAuthRouter = express.Router();
mainAuthRouter.post("/signup", authController.signup);
mainAuthRouter.post("/login", authController.login);
mainAuthRouter.get("/logout", authController.logout); // GET for simplicity

// NEW ROUTE FOR ADMIN TO UPDATE USER ROLE
mainAuthRouter.patch(
  "/:userId/role", // Path to update a specific user's role
  authMiddleware.protect, // Step 1: Ensure the requester is logged in
  permissionsMiddleware.restrictTo("admin"), // Step 2: Ensure the logged-in user is an 'admin'
  authController.updateUserRoleByAdmin // Step 3: Call the controller function
);

// Comment Routes (from routes/commentRoutes.js)
const mainCommentRouter = express.Router();
mainCommentRouter.use(authMiddleware.protect); // Protect all comment routes

mainCommentRouter
  .route("/")
  .get(commentController.getAllComments)
  .post(
    permissionsMiddleware.restrictTo("user", "moderator", "admin"),
    commentController.createComment
  );

mainCommentRouter
  .route("/:id")
  .get(commentController.getComment)
  .patch(
    // Using PATCH for partial updates
    permissionsMiddleware.canManageComment,
    commentController.updateComment
  )
  .delete(
    permissionsMiddleware.canManageComment,
    commentController.deleteComment
  );

app.use("/api/v1/users", mainAuthRouter); // Prefix user routes with /api/v1/users
app.use("/api/v1/comments", mainCommentRouter); // Prefix comment routes with /api/v1/comments

// Test route
app.get("/api/v1/test", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "API test endpoint is working!",
  });
});

// --- Undefined Route Handler ---
// This should be placed AFTER all other specific route handlers
app.all("*", (req, res, next) => {
  // For favicon.ico, we can send a 204 No Content if we don't want to serve an icon
  if (req.originalUrl === "/favicon.ico") {
    return res.status(204).end();
  }
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// --- Global Error Handling Middleware ---
// This middleware catches all errors passed by next(err)
// It must have 4 arguments (err, req, res, next) for Express to recognize it as an error handler
const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500; // Default to 500 Internal Server Error
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    // Development: send detailed error
    console.error("ERROR 💥:", err);
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack,
    });
  } else if (process.env.NODE_ENV === "production") {
    // Production: send generic error for programming errors, operational errors are fine
    let error = { ...err }; // Create a hard copy
    error.message = err.message; // Important to copy message

    // Log all errors in production for debugging
    console.error("PRODUCTION ERROR 💥:", error);

    // Handle specific Mongoose errors for more user-friendly messages
    if (error.name === "CastError")
      error = new AppError(`Invalid ${error.path}: ${error.value}.`, 400);
    if (error.code === 11000) {
      // Mongoose duplicate key
      const value = Object.keys(error.keyValue)[0];
      error = new AppError(
        `Duplicate field value for: ${value}. Please use another value.`,
        400
      );
    }
    if (error.name === "ValidationError") {
      const errors = Object.values(error.errors).map((el) => el.message);
      const message = `Invalid input data. ${errors.join(". ")}`;
      error = new AppError(message, 400);
    }
    if (error.name === "JsonWebTokenError")
      error = new AppError("Invalid token. Please log in again.", 401);
    if (error.name === "TokenExpiredError")
      error = new AppError("Your token has expired. Please log in again.", 401);

    if (error.isOperational) {
      // Operational, trusted error: send message to client
      return res.status(error.statusCode).json({
        status: error.status,
        message: error.message,
      });
    }
    // Programming or other unknown error: don't leak error details
    return res.status(500).json({
      status: "error",
      message: "Something went very wrong! Please try again later.",
    });
  }
};
app.use(globalErrorHandler);

// --- Start Server ---
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(
    `Server running in ${process.env.NODE_ENV} mode on port ${PORT}...`
  );
});

// --- Unhandled Rejection Handler (e.g., DB connection failure outside initial connect) ---
process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION! 💥 Shutting down...");
  console.error(err.name, err.message, err.stack);
  server.close(() => {
    // Gracefully close server before exiting
    process.exit(1); // 1 indicates an uncaught exception
  });
});

// --- SIGTERM Handler (for graceful shutdown on platforms like Heroku) ---
process.on("SIGTERM", () => {
  console.log("👋 SIGTERM RECEIVED. Shutting down gracefully...");
  server.close(() => {
    console.log("💥 Process terminated!");
    // mongoose.connection.close(false, () => { // Mongoose 6+
    //     console.log('MongoDb connection closed.');
    //     process.exit(0);
    // });
    process.exit(0); // 0 indicates success
  });
});
