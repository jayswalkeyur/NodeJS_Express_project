const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    // Get the token from the request body, query parameters, or headers
    const token = req.body.token || req.query.token || req.headers["x-access-token"];

    // If no token is provided, return a 403 Forbidden error
    if (!token) {
        return res.status(403).send("A token is required for authentication");
    }

    try {
        // Verify the token using the secret key from environment variables
        const decoded = jwt.verify(token, process.env.TOKEN_KEY);

        // Attach the decoded user information to the request object
        req.user = decoded;
    } catch (err) {
        // If the token is invalid, return a 401 Unauthorized error
        return res.status(401).send("Invalid Token");
    }

    // If everything is good, proceed to the next middleware
    return next();
};

module.exports = verifyToken;
