// import jwt from 'jsonwebtoken'; 
// import { User } from "../models/user.model.js";
// import ErrorHandler from '../middleware/Error.js';
// import { catchAsyncError } from '../middleware/catchAsyncError.js'
// import generateOtp from '../utils/generateOtp.js';
// import sendEmail from '../utils/email.js';

// const signToken = (id) => {
//     return jwt.sign({ id }, process.env.JWT_SECRET, {
//         expiresIn: process.env.JWT_EXPIRES_IN
//     });
// };

// const createSendToken = (user, statusCode, res, message) => {
//     const token = signToken(user._id);

//     const cookieOptions = { 
//         expires: new Date(
//             Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
//         ),
//         httpOnly: true,
//         secure: process.env.NODE_ENV === 'production',
//         sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'Lax'
//     };

//     res.cookie('token', token, cookieOptions);

//     user.password = undefined;
//     user.otp = undefined;

//     res.status(statusCode).json({
//         status: 'success',
//         message,
//         token,
//         data: {
//             user
//         }
//     });
// };

// export const Signup = catchAsyncError(async (req, res, next) => {
//     const { email, password, name } = req.body;

//     if (!email || !password || !name) {
//         return next(new ErrorHandler("All fields are required", 400));
//     }

//     const userAlreadyExists = await User.findOne({ email });
//     if (userAlreadyExists) {
//         return next(new ErrorHandler("Email is already registered.", 409)); // Changed 404 to 409
//     }

//     const otp = generateOtp();
//     const otpExpires = Date.now() + 24 * 60 * 60 * 1000;

//     const user = new User({ email, password, name, otp, otpExpires });

//     await user.save(); // Password is hashed automatically by the schema

//     try {
//         await sendEmail({
//             email: user.email,
//             subject: "OTP for email verification",
//             html: `<h1>Your OTP is: ${otp}</h1>`
//         });

//         createSendToken(user, 200, res, "Registration successful");
//     } catch (error) {
//         await User.findByIdAndDelete(user.id);
//         return next(new ErrorHandler("There is an error sending the email. Try again.", 500));
//     }

//     res.status(201).json({
//         success: true,
//         message: "User created successfully",
//         user: { ...user._doc, password: undefined }
//     });
// });


// export const verifyEmail = catchAsyncError(async(req,res,next)=>{
//     const {otp} = req.body;

//     if(!otp){
//         return next(new ErrorHandler("Otp is missing",400));
//     }

//     const user = req.user;

//     if(user.otp !== otp){
//         return next(new ErrorHandler("Invalid OTP",400))
//     }

//     if(Date.now() > user.otpExpires ){
//         return next(new ErrorHandler("Otp has expired.Please request a new OTP",400))
//     }


//     user.isVerified = true;
//     user.otp = undefined;
//     user.otpExpires = undefined;

//     await user.save({
//         validateBeforeSave : false
//     })

//     createSendToken(user,200,res,"Email has been verified.");

// })

// export const resendOTP = catchAsyncError(async(req,res,next)=>{
//     const {email} = req.body;

//     if(!email){
//         return next(new ErrorHandler("Email is required to resend OTP",400))
//     }

//     const user = await User.findOne({email})
//     if(!user){
//         return next(new ErrorHandler("User not Found",404))
//     }

//     if(user.isVerified){
//         return next(new ErrorHandler("This Account is already Verified",400))
//     }

//     const newOtp = generateOtp();

//     user.otp = newOtp;
//     user.otpExpires = Date.now() + 24 * 60 * 60 * 1000;

//     await user.save({ validateBeforeSave:false });

//     try {
//         await sendEmail({
//             email:user.email,
//             subject: 'Resend Otp for email verification',
//             html: `<h1>Your new Otp is : ${newOtp}</h1>`
//         })

//         res.status(200).json({
//             status: 'success',
//             message: 'A new Otp has sent to your email',

//         })
//     } catch (error) {
//         user.otp = undefined;
//         user.otpExpires = undefined;
        
//         await user.save({
//             validateBeforeSave: false
//         })

//         return next(new ErrorHandler("There is an error sending this email ! Please try again",500))
//     }
// }) 


// export const Login = catchAsyncError(async (req, res, next) => {
//     const { email, password } = req.body;

//     if (!email || !password) {
//         return next(new ErrorHandler("Please provide email and password", 400));
//     }

//     const user = await User.findOne({ email }).select("+password");
//     if (!user) {
//         return next(new ErrorHandler("Incorrect Email or Password", 401));
//     }

//     const isMatch = await user.correctPassword(password, user.password);
//     if (!isMatch) {
//         return next(new ErrorHandler("Incorrect Email or Password", 401));
//     }

//     createSendToken(user, 200, res, "Login Successful");
// });



// export const Logout = catchAsyncError(async(req,res,next) =>{
//        res.cookie("token","LoggedOut",{
//         expires: new Date(Date.now() + 10 * 1000),
//         httpOnly:true,
//         secure: process.env.NODE_ENV === 'production'
//        });

//        res.status(200).json({
//         status:"success",
//         message: "Logged out successfully"
//        })

// })

// export const forgotPassword = catchAsyncError(async(req,res,next)=>{
//     const {email} = req.body;
//     const user = await User.findOne({ email });

//     if(!user){
//         return next(new ErrorHandler("No user found",404))
//     }

//     const otp = generateOtp();

//     user.resetPasswordOtp = otp;
//     user.resetPasswordOtpExpiresAt = Date.now() + 300000;


//     await user.save({validateBeforeSave: false});


//     try {
//         await sendEmail({
//             email: user.email,
//             subject: "Reset Password Otp(valid for 5 min)",
//             html: `<h1>Your reset password OTP is: ${otp}</h1>`
//         })

//         res.status(200).json({
//             success: 'success',
//             message: "Password reset otp sent to your email",
//         })
//     } catch (error) {
//         user.resetPasswordOtp = undefined;
//         user.resetPasswordOtpExpiresAt = undefined;
//         await user.save({ validateBeforeSave: false });
//         return next(new ErrorHandler("There was an error sending this email", 500))
//     }
// })

// export const resetPassword = catchAsyncError(async(req,res,next)=>{
//     const {email,otp,password} = req.body;

//     const user = await User.findOne(
//         {email,
//         resetPasswordOtp:otp,
//         resetPasswordOtpExpiresAt:{$gt:Date.now()}
//      }
//     );

//     if(!user){
//         return next(new ErrorHandler("No user found",400))
//     }

//     user.password = password;
//     user.resetPasswordOtp = undefined;
//     user.resetPasswordOtpExpiresAt = undefined;

//     await user.save();

//     createSendToken(user, 200, res, "Password reset successfully");

// })



// export const checkAuth = async(req,res,next) =>{
//     try {
//         const user = await User.findById(req.userId).select("-password")
//         if(!user){
//             return next(new ErrorHandler("User not found",404))
//         }

//         res.status(200).json({
//             success:true,
//             user
//         })
//     } catch (error) {
//         return next(new ErrorHandler("User not found",404))
//     }
// }





import bcrypt from "bcryptjs";
import crypto from "crypto";
import { User } from "../models/user.model.js";
import sendEmail from '../utils/email.js';
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";

// Signup Controller
export const Signup = async (req, res) => {
	const { email, password, name } = req.body;

	try {
		if (!email || !password || !name) {
			throw new Error("All fields are required");
		}

		const userAlreadyExists = await User.findOne({ email });
		console.log("userAlreadyExists", userAlreadyExists);

		if (userAlreadyExists) {
			return res.status(400).json({ success: false, message: "User already exists" });
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const otp = Math.floor(100000 + Math.random() * 900000).toString();

		const user = new User({
			email,
			password: hashedPassword,
			name,
			otp,
			otpExpires: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
		});

		await user.save();

		// jwt
		generateTokenAndSetCookie(res, user._id);

		await sendEmail({
                        email: user.email,
                        subject: "OTP for email verification",
                        html: `<h1>Your OTP is: ${otp}</h1>`
        });

		res.status(201).json({
			success: true,
			message: "User created successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		res.status(400).json({ success: false, message: error.message });
	}
};


// VerifyEmail Controller
export const verifyEmail = async (req, res) => {
	const { otp } = req.body;
	try {
		const user = await User.findOne({
			otp: otp,
			otpExpires: { $gt: Date.now() },
		});

		if (!user) {
			return res.status(400).json({ success: false, message: "Invalid or expired verification code" });
		}

		user.isVerified = true;
		user.otp = undefined;
		user.otpExpires = undefined;
		await user.save();

		

		res.status(200).json({
			success: true,
			message: "Email verified successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("error in verifyEmail ", error);
		res.status(500).json({ success: false, message: "Server error" });
	}
};

// Login Controller
export const Login = async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email });

		if (!user) {
			return res.status(400).json({ success: false, message: "Email is not Registered" });
		}

		// Debugging - Log user object
		console.log("User found:", user);

		if (!user.password) {
			return res.status(500).json({ success: false, message: "User password is missing in the database." });
		}

		const isPasswordValid = await bcrypt.compare(password, user.password);
		if (!isPasswordValid) {
			return res.status(400).json({ success: false, message: "Password is wrong" });
		}

		generateTokenAndSetCookie(res, user._id);

		user.lastLogin = new Date();
		await user.save();

		res.status(200).json({
			success: true,
			message: "Logged in successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("Error in login:", error);
		res.status(400).json({ success: false, message: error.message });
	}
};


// Logout Controller
export const Logout = async (req, res) => {
	res.clearCookie("token");
	res.status(200).json({ success: true, message: "Logged out successfully" });
};



// Reset Password controller
export const resetPassword = async (req, res) => {
    const { email, otp, password } = req.body;

    try {
        const user = await User.findOne({
            email,
            resetPasswordOtp: otp,
            resetPasswordOtpExpiresAt: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
        }

        // Hash the new password before saving
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordOtp = undefined;
        user.resetPasswordOtpExpiresAt = undefined;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully",
        });

    } catch (error) {
        console.log("Error in resetPassword:", error);
        return res.status(500).json({ success: false, message: "Server error" });
    }
};



// Forgot Password
export const forgotPassword = async(req,res)=>{
    const {email} = req.body;
    const user = await User.findOne({ email });

    if(!user){
        return res.status(404).json({ success: false, message: "No user found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.resetPasswordOtp = otp;
    user.resetPasswordOtpExpiresAt = Date.now() + 300000;


    await user.save();


    try {
        await sendEmail({
            email: user.email,
            subject: "Reset Password Otp(valid for 5 min)",
            html: `<h1>Your reset password OTP is: ${otp}</h1>`
        })

        res.status(200).json({
            success: 'success',
            message: "Password reset otp sent to your email",
        })
    } catch (error) {
        user.resetPasswordOtp = undefined;
        user.resetPasswordOtpExpiresAt = undefined;
        await user.save();
        return res.status(500).json({ success: false, message: "There was an error sending this email" });
    }
}





// CHeck auth Controller
export const checkAuth = async (req, res) => {
	try {
		const user = await User.findById(req.userId);
		if (!user) {
			return res.status(400).json({ success: false, message: "User not found" });
		}

		res.status(200).json({ success: true, user });
	} catch (error) {
		console.log("Error in checkAuth ", error);
		res.status(400).json({ success: false, message: error.message });
	}
};