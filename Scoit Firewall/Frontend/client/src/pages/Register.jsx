import { Eye, EyeOff, Loader, Lock, Mail, User2 } from "lucide-react";
import Input from "../components/Input";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";
import axios from "axios";
import { API_URL } from "../utils/api.js";
import { toast } from "sonner"

const Register = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({ name: "", email: "", password: "" });
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await axios.post(`${API_URL}/signup`, formData, {
        withCredentials: true,
        headers: { "Content-Type": "application/json" },
      });

      console.log("Server Response:", response.data);
      toast.success("Registration successful!");
      navigate("/verify-email"); // Redirect to dashboard after signup
    } catch (error) {
      console.error("Axios Error:", error.response ? error.response.data : error);
      toast.error(error.response?.data?.message || "Failed to register.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full flex justify-center my-16 lg:my-14">
      <div className="w-auto h-auto max-w-sm sm:max-w-sm lg:max-w-md bg-gray-300 rounded-xl shadow-lg px-4 sm:px-8 lg:px-10 py-4">
        <h2 className="text-2xl font-bold text-center text-black mb-6">Create Account</h2>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input icon={User2} type="text" placeholder="Full Name" name="name" value={formData.name} onChange={handleChange} />
          <Input icon={Mail} type="email" placeholder="Email Address" name="email" value={formData.email} onChange={handleChange} />
          <Input icon={Lock} type={showPassword ? "text" : "password"} placeholder="Password" name="password" value={formData.password} onChange={handleChange} />
          <button
                  type="button"
                  className="absolute mx-56 mt-[154px]"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-base-content/40" />
                  ) : (
                    <Eye className="h-5 w-5 text-base-content/40" />
                  )}
                </button>

          <PasswordStrengthMeter password={formData.password} />

          <button className="w-full bg-black text-white p-3 rounded-md text-sm sm:text-base font-light hover:bg-gray-800 transition" type="submit" disabled={isLoading}>
            {isLoading ? <Loader className="animate-spin mx-auto" size={24} /> : "Register"}
          </button>
        </form>

        <p className="text-center text-sm sm:text-base mt-3 sm:mt-4 text-gray-700">
          Already have an account?{" "}
          <Link to="/login" className="text-black font-semibold hover:underline">Login</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
