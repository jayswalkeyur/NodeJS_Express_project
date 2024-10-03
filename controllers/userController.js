'use strict';
const nodemailer = require("nodemailer");
const mongoose = require("mongoose"),
    User = mongoose.model("user"),
    session = mongoose.startSession,
    jwt = require("jsonwebtoken"),
    auth = require("../middleware/auth"),
    bcrypt = require("bcrypt");
    

exports.get_all_users = function(req, res) {
    User.find({}, function(err, user) {
        if (err)
            res.send(err);
        res.json(user);
    })
}


exports.find_user_byId = function(req, res) {
    User.findById(req.params.Id, function(err, user) {
        if (err)
            res.status(404).send("User Does not exist in the database");
        res.json(user);
    });
};

exports.register_a_user = async function(req, res) {
    try {
        // Get user input
        const { firstName,lastName, email, password, role } = req.body;

        // Validate user input
        if (!(firstName&& lastName && email && password && role)) {
            return res.status(400).send("All input is required");
        }

        // Check if user already exists
        const oldUser = await User.findOne({ email: email.toLowerCase() });

        if (oldUser) {
            return res.status(409).send("User Already Exist. Please Login");
        }

        // Encrypt user password
        const encryptedPassword = await bcrypt.hash(password, 10);

        // Create user in the database
        const user = await User.create({
            firstName,
            lastName,
            email: email.toLowerCase(),
            password: encryptedPassword,
            role
        });

        // Check if TOKEN_KEY is defined
        if (!process.env.TOKEN_KEY) {
            throw new Error("TOKEN_KEY is not defined. Please set it in your environment variables.");
        }

        // Create token
        const token = jwt.sign(
            { user_id: user._id, email: user.email },
            process.env.TOKEN_KEY,
            { expiresIn: "2h" }
        );

        // Save user token
        user.token = token;

        // Return the new user with token
        return res.status(201).json(user);

    } catch (err) {
        // Handle any errors
        console.error(err); // Log the error for debugging
        return res.status(500).json({ message: err.message });
    }
}




exports.login_a_user = async function(req, res) {
    try {
        const { email, password } = req.body;

        // Validate user input
        if (!(email && password)) {
            return res.status(400).send("All input is required");
        }

        // Find the user by email
        const user = await User.findOne({ email });

        // Check if the user exists and if the password is correct
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send("Invalid Credentials");
        }

        // Check if the user's role is "admin"
        if (user.role !== "admin") {
            return res.status(403).send("Access denied: You must be an admin to log in.");
        }

        // Generate a token if the role is admin and credentials are correct
        const token = jwt.sign(
            { user_id: user._id, email: user.email },
            process.env.TOKEN_KEY,
            { expiresIn: "2h" }
        );

        // Save the token
        user.token = token;
        await user.save();

        // Generate email verification token
        const verificationToken = jwt.sign(
            { user_id: user._id, email: user.email },
            process.env.TOKEN_KEY,
            { expiresIn: "1d" } // Token valid for 1 day
        );

        // Prepare verification email
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Verify Your Email Address',
            text: `Please verify your email by clicking the following link: ${process.env.BASE_URL}/verify-email?token=${verificationToken}`
        };

        // Send verification email
        await transporter.sendMail(mailOptions);

        // Respond with the token and a message about email verification
        return res.status(201).json({
            token: token,
            message: "Login successful. Please check your email for a verification link."
        });

    } catch (err) {
        // Handle errors and send a 500 response
        return res.status(500).json({ message: err.message });
    }
};


//testing authorization
exports.auth = function(req, res) {
    res.status(200).send("Welcome to Api built with NodeJs");
}