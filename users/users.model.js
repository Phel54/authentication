require("dotenv").config();
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const crypto = require("crypto");

const userSchema = new Schema ({
    fname: {
        type:String, 
        required:true,
        trim:true
    },
    lname:{
        type:String, 
        required:true,
        trim:true
    },
    phone:{
        type:String, 
        required:true,
        trim:true
    },
    email: { 
        type:String, 
        required:true,
        trim:true,
        unique:true
    },
    password: {
        type:String, 
        required:true,
        trim:true
    },		
    isActive: {
        type: Boolean,
        default: true,
    },
    resetPasswordToken: String,
    resetPasswordExpires: String,
},  {timestamps: true}, )

const User = mongoose.model("Users", userSchema, "users");

module.exports= User; 