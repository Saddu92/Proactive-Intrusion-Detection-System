import { useEffect, useRef, useState } from "react";
import {  useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/authStore.js";
import { toast } from "sonner"
import axios from "axios";
import { API_URL } from "../utils/api.js";
import { Loader } from "lucide-react";

const EmailVerification = () => {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const inputRefs = useRef([]);
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const { error, isLoading } = useAuthStore();
  const setAuthState = useAuthStore.setState;


  const handleResendOtp = async () =>{
    setLoading(true);
    try {
      await axios.post(`${API_URL}/resend-otp`,{
        withCredentials:true
      })
      toast.success("New OTP is sent to your email")
    } catch (error) {
      toast.error(error.response.data.message);
    }finally{
      setLoading(false);
    }
  }



  const handleChange = (index, value) => {
    const newOtp = [...otp];

    if (value.length > 1) {
      const pastedCode = value.slice(0, 6).split("");
      for (let i = 0; i < 6; i++) {
        newOtp[i] = pastedCode[i] || "";
      }
      setOtp(newOtp);
      inputRefs.current[5]?.focus();
    } else {
      newOtp[index] = value;
      setOtp(newOtp);
      if (value && index < 5) {
        inputRefs.current[index + 1]?.focus();
      }
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleSubmit = async (e) => {
    setLoading(true); // Set loading state to true
    e?.preventDefault();
    setAuthState({ error: null }); // Reset error

    const otpValue = otp.join("");  // Join the OTP array to create a single string
    console.log("OTP Value Sent:", otpValue);  // Debugging line to log OTP before sending it
    
    if (otpValue.length < 6) {
      toast.error("Please enter all 6 digits.");
      setLoading(false);  // Reset loading state if OTP is incomplete
      return;
    }

    try {
      const response = await axios.post(`${API_URL}/verify-email`, { otp: otpValue }, {
        withCredentials: true,
        headers: { "Content-Type": "application/json" },
      });

      console.log("Response from Backend:", response);  // Log response to verify its structure
      const verifiedUser = response.data.user; // Adjust this if the response structure is different
      setAuthState({ user: verifiedUser, isAuthenticated: true });
      toast.success("Email verified successfully!");
      navigate("/");
    } catch (error) {
      console.error("Verification Error:", error);
      const errorMessage = error.response?.data?.message || "Failed to verify email. Please try again.";
      toast.error(errorMessage);  // Display the specific error message
    } finally {
      setLoading(false);  // Set loading state to false after request completes
    }
  };

  useEffect(() => {
    if (otp.every((digit) => digit !== "")) {
      handleSubmit();
    }
  }, [otp]);

  return (
    <div className="w-full flex justify-center px-3 my-40">
      <div className="w-full max-w-sm sm:max-w-md lg:max-w-lg bg-gray-300 rounded-xl shadow-lg px-5 sm:px-8 lg:px-10 py-6">
        <h2 className="text-lg sm:text-xl font-bold text-center mb-4">Verify Your Email</h2>
        <p className="text-gray-600 text-sm sm:text-base text-center mb-5">
          Enter the 6-digit code sent to your email.
        </p>
        <form onSubmit={handleSubmit} className="space-y-6 w-full">
          <div className="flex justify-center gap-2 sm:gap-4">
            {otp.map((_, index) => (
              <input
                key={index}
                ref={(el) => (inputRefs.current[index] = el)}
                type="text"
                maxLength="1"
                className="w-9 h-9 sm:w-12 sm:h-12 text-center border border-gray-400 rounded-md focus:outline-none focus:border-black text-lg"
                value={otp[index]}
                onChange={(e) => handleChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                autoComplete="one-time-code"
              />
            ))}
          </div>
          {error && <p className="text-red-500 font-semibold text-xs mt-2 lg:mx-8">{error}</p>}
          <button
            disabled={isLoading || loading}
            type="submit"
            className="mt-4 w-full bg-black text-white p-2 sm:p-3 rounded-md font-light hover:bg-gray-800 transition duration-300"
          >
            {loading ? "Verifying..." : "Verify Email"}
          </button>
          <p className="text-gray-600 text-sm sm:text-base text-center mt-4 font-normal">
            Didn&apos;t receive the code?{" "}
           {!loading && <button
              type="button"
              onClick={handleResendOtp}
              className="text-black font-semibold focus:outline-none"
            >
              Resend Code
            </button>}
            {
              loading && <button className='mt-6'>
                <Loader className="animate-spin"/>
              </button>
            }
            </p>
        </form>
      </div>
    </div>
  );
};

export default EmailVerification;
