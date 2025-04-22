import { useState } from "react";
import axios from "axios";
import { Link,  useNavigate } from "react-router-dom";
import {API_URL} from "../utils/api.js";
import { toast } from "sonner";
import {useAuthStore} from "../store/authStore.js";
import Input from "../components/Input.jsx";
import { ArrowLeft, Loader, Mail } from "lucide-react";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [isSubmitted,setIsSubmitted] = useState(false);
  const {isLoading,forgotPassword} = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
   
    try {
      const response = await axios.post(`${API_URL}/forgot-password`, { email }, {
        withCredentials: true,
        headers: { "Content-Type": "application/json" },
      });
      
      console.log("Server Response:", response.data);
      toast.success("Otp is sent to your email!");
      navigate('/reset-password')
    } catch (error) {
      console.error("Login Error:", error.response ? error.response.data : error);
      toast.error(error.response?.data?.message || "Failed to log in.");
    } finally {
      setIsSubmitted(true);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 px-5 dark:bg-gray-900">
      <div className="bg-white dark:bg-gray-800 lg:p-9 md:p-8 p-3 rounded-lg shadow-lg max-w-md  transition-all duration-300 flex flex-col">
        <h2 className="text-3xl font-bold text-gray-700 dark:text-white text-center mb-5">
          Forgot Password
        </h2>
  
        {!isSubmitted ? (
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
                className=" border border-gray-300 dark:border-gray-600  rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 dark:bg-gray-700 dark:text-white"
                placeholder="Enter your email"
                required
                size={22}
              />
            </div>
  
            {/* Submit Button */}
            <button
              type="submit"
              className="px-20 mx-3 bg-black text-white lg:py-2 py-3 text-nowrap  rounded-md text-sm sm:text-base font-light hover:bg-gray-800 transition"
              disabled={isLoading}
            >
              {isLoading ? (
                <Loader className="animate-spin mx-auto" size={23} />
              ) : (
                "Send Reset Link"
              )}
            </button>
          </form>
        ) : (
          <div className="text-center">
            <Mail className="mx-auto text-blue-500" size={32} />
            <p className="text-gray-600 dark:text-gray-300 mt-4">
              If an account exists for{" "}
              <span className="font-semibold">{email}</span>, you will receive a
              password reset link shortly.
            </p>
          </div>
        )}
  
        {/* Back to Login inside the box */}
        <div className="mt-6 border-t border-gray-300 dark:border-gray-700 pt-4 text-center">
          <Link
            to="/login"
            className="flex items-center justify-center text-blue-600 dark:text-blue-400 hover:underline"
          >
            <ArrowLeft className="h-5 w-5 mr-2" /> Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
};  

export default ForgotPassword;