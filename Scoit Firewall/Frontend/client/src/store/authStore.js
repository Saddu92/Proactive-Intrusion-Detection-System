import { create } from "zustand";
import axios from "axios";

const API_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000/api/auth";

axios.defaults.withCredentials = true;

export const useAuthStore = create((set) => ({
  user: null,
  isAuthenticated: false,
  error: null,
  isLoading: false,
  isCheckingAuth: true, // Used for checking user session on app load

  /** 🔹 Signup Function */
  signup: async (name, email, password) => {
    set({ isLoading: true, error: null });
    try {
      const response = await axios.post(`${API_URL}/signup`, { name, email, password });
      set({ user: response.data.user, isAuthenticated: true, isLoading: false });
      return response.data;
    } catch (error) {
      set({ error: error.response?.data?.message || "Error signing up", isLoading: false });
      throw error;
    }
  },

  /** 🔹 Login Function */
  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const response = await axios.post(`${API_URL}/login`, { email, password });
      set({ user: response.data.user, isAuthenticated: true, isLoading: false });
      return response.data;
    } catch (error) {
      set({ error: error.response?.data?.message || "Error logging in", isLoading: false });
      throw error;
    }
  },

  /** 🔹 Verify Email */
verifyEmail: async (code) => {
  set({ isLoading: true, error: null });

  try {
    const response = await axios.post(`${API_URL}/verify-email`, { code });

    set({ user: response.data.user, isAuthenticated: true, isLoading: false });

    return response.data;
  } catch (error) {
    set({ error: error.response?.data?.message || "Error verifying email", isLoading: false });
    throw error;
  }
},
  

  /** 🔹 Logout Function */
  logout: async () => {
    set({ isLoading: true, error: null });
    try {
      await axios.post(`${API_URL}/logout`);
      set({ user: null, isAuthenticated: false, isLoading: false });
    } catch (error) {
      set({ error: "Error logging out", isLoading: false });
    }
  },


  forgotPassword: async (email) => {
    set({ isLoading: true, error: null });
    try {
      const response = await axios.post(`${API_URL}/forgot-password`, { email });
      set({message: response.data.message , isLoading: false,error: error.response.data.message || "Error sending reset password email" });

    } catch (error) {
      set({ error: error.response?.data?.message || "Error sending reset link", isLoading: false });
      throw error;
    }
  },

  resetPassword: async (email, otp, password) => {
    set({ isLoading: true, error: null });
    try {
      const response = await axios.post(`${API_URL}/reset-password`, { email, otp, password });
      set({ message: response.data.message, isLoading: false });
    } catch (error) {
      set({ error: error.response?.data?.message || "Error resetting password", isLoading: false });
      throw error;
    }
  },

  /** 🔹 Check if user is already logged in (on app load) */
  checkAuth: async () => {
    set({ isCheckingAuth: true });
    try {
      const response = await axios.get(`${API_URL}/check-auth`);
      set({ user: response.data.user, isAuthenticated: true, isCheckingAuth: false });
    } catch (error) {
      set({ user: null, isAuthenticated: false, isCheckingAuth: false });
    }
  },
}));


export default useAuthStore;