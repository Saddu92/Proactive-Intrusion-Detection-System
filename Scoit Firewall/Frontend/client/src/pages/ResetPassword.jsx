import { useState } from "react";
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";
import { API_URL } from "../utils/api.js";
import { toast } from "sonner";
import Input from "../components/Input.jsx";
import { ArrowLeft, Loader, Lock, Mail, Key, EyeOff, Eye } from "lucide-react";

const ResetPassword = () => {
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    try {
      const response = await axios.post(`${API_URL}/reset-password`, 
        { email, otp, password }, 
        { withCredentials: true, headers: { "Content-Type": "application/json" } }
      );
      
      console.log("Server Response:", response.data);
      toast.success("Password reset successfully!");
      navigate("/login");
      
    } catch (error) {
      console.error("Reset Password Error:", error.response?.data?.message || error);
      toast.error(error.response?.data?.message || "Failed to reset password.");
      
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 px-4 dark:bg-gray-900">
      <div className="bg-white dark:bg-gray-800 lg:p-9 md:p-8 sm:p-6 p-4 rounded-lg shadow-lg max-w-md  transition-all duration-300 flex flex-col">
        <h2 className="text-3xl font-bold text-gray-700 dark:text-white text-center mb-6">
          Reset Password
        </h2>
  
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Email Input */}
          <div>
            <label className="block text-gray-600 dark:text-gray-300 text-sm mb-2 mx-3">
              Email Address
            </label>
            <Input
              icon={Mail}
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full border border-gray-300 dark:border-gray-600 px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
              placeholder="Enter your email"
              required
            />
          </div>
  
          {/* OTP Input */}
          <div>
            <label className="block text-gray-600 dark:text-gray-300 text-sm mb-2 mx-3">
              OTP
            </label>
            <Input
              icon={Key}
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              className="w-full border border-gray-300 dark:border-gray-600 px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
              placeholder="Enter OTP"
              required
            />
          </div>
  
          {/* New Password Input */}
          <div>
            <label className="block text-gray-600 dark:text-gray-300 text-sm mb-2 mx-3">
              New Password
            </label>
            <Input
              icon={Lock}
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full border border-gray-300 dark:border-gray-600 px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
              placeholder="Enter new password"
              required
            />
          <button
                  type="button"
                  className="absolute mx-56 mt-[-40px]"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-base-content/40" />
                  ) : (
                    <Eye className="h-5 w-5 text-base-content/40" />
                  )}
                </button>
          </div>
  
          {/* Submit Button */}
          <button
            type="submit"
            className="px-16 mx-3  bg-black text-white py-3 text-base rounded-md font-medium hover:bg-gray-800 transition"
            disabled={isLoading}
          >
            {isLoading ? <Loader className="animate-spin mx-auto" size={23} /> : "Reset Password"}
          </button>
        </form>
  
        {/* Back to Login inside the box */}
        <div className="mt-6 border-t border-gray-300  dark:border-gray-700 pt-4 text-center">
          <Link
            to="/login"
            className="flex items-center justify-center  hover:underline"
          >
            <ArrowLeft className="h-5 w-5 mr-2" /> Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
  
};

export default ResetPassword;
