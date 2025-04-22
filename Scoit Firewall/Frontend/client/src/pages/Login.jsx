import { Eye, EyeOff, Loader, Lock, Mail } from "lucide-react";
import Input from "../components/Input";
import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { toast } from "sonner"

import axios from "axios";
import { API_URL } from "../utils/api.js";

const Login = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();
  const [formData, setFormData] = useState({  email: "", password: "" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await axios.post(`${API_URL}/login`, formData, {
        withCredentials: true,
        headers: { "Content-Type": "application/json" },
      });
      
      console.log("Server Response:", response.data);
      toast.success("Login successful!");
      navigate("/");
    } catch (error) {
      console.error("Login Error:", error.response ? error.response.data : error);
      toast.error(error.response?.data?.message || "Failed to log in.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full flex justify-center my-16 lg:my-14">
      <div className="w-auto max-w-sm sm:max-w-sm lg:max-w-md bg-gray-300 rounded-xl shadow-lg px-4 sm:px-8 lg:px-10 py-4">
        <h2 className="text-2xl font-bold text-center text-black mb-6">Welcome Back</h2>
        
        <form onSubmit={handleSubmit} className="flex flex-col gap-2">
          <Input icon={Mail} type="email" placeholder="Email Address" name="email" value={formData.email} onChange={handleChange} />
          <Input icon={Lock} type={showPassword ? "text" : "password"} placeholder="password" name="password" value={formData.password} onChange={handleChange} />
          <button
                  type="button"
                  className="absolute mx-56 mt-[75px]"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-base-content/40" />
                  ) : (
                    <Eye className="h-5 w-5 text-base-content/40" />
                  )}
                </button>

          <div className="flex justify-end">
            <Link to="/forgot-password" className="text-sm text-gray-700 hover:underline">Forgot Password?</Link>
          </div>

          <button className="w-full bg-black text-white p-3 rounded-md text-sm sm:text-base font-light hover:bg-gray-800 transition" type="submit" disabled={isLoading}>
            {isLoading ? <Loader className="animate-spin mx-auto" size={24} /> : "Login"}
          </button>
        </form>

        <p className="text-center text-sm sm:text-base mt-3 sm:mt-4 text-gray-700">
          Don&apos;t have an account? {" "}
          <Link to="/register" className="text-black font-semibold hover:underline">Register</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;