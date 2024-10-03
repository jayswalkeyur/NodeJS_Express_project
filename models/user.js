const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: "Please enter the FirstName" },
    lastName: { type: String, required: "Please enter the LastName" },
    email: { type: String, required: "Email address is required", match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'] },
    password: { type: String, required: "Password is required" },
    role:{type:String, enum : ['admin','customer'], required: "role is required"},
    token:{type:"String"}
});

module.exports = mongoose.model("user", userSchema);