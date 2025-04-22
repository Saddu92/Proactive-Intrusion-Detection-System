
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:[true,"Password is required"],
        
        
    },
    name:{
        type:String,
        required:true
    },
    lastLogin : {
        type:Date,
        default:Date.now
    },
    isVerified: {
        type:Boolean,
        default:false
    },
    otp:{
        type:String,
        default:null
    },
    otpExpires : {
        type:Date,
        default:null
    },
    resetPasswordOtp :{
        type :String,
        default:null
    },
    resetPasswordOtpExpiresAt :{
        type:Date,
        default:null
    },
    
},{
    timestamps:true
})





export const User = mongoose.model("User",userSchema);