import express, { Router } from 'express'
import { Login, Logout, Signup ,resetPassword, verifyEmail,checkAuth,forgotPassword} from '../controllers/user.controller.js';
import { verifyToken } from '../middleware/verifyToken.js';

const router = express.Router();


router.post('/signup', Signup)
router.post('/login',Login)
router.post('/logout',Logout)
router.post('/verify-email',verifyToken,verifyEmail)
// router.post('/resend-otp',verifyToken,resendOTP)
router.post('/forgot-password',forgotPassword)
router.post('/reset-password',resetPassword)
router.get("/check-auth",verifyToken,checkAuth);





export default router;