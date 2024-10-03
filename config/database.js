const mongoose = require("mongoose");
require("dotenv").config();

const MONGO_URI = process.env.MONGO_URI;
mongoose.set('strictQuery', true);

exports.connect = () => {

    //Connecting to the database
    mongoose.connect(MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(()=>{
        console.log("Successfully Connected to the database")
    })
    .catch((error)=>{
        console.log("database connection failed. exiting now...");
        console.log(error.message);
        process.exit(1)
        
    })

}