import { createBrowserRouter, Outlet, RouterProvider } from "react-router-dom"
import About from "./pages/About"
import Login from "./pages/Login"
import Register from "./pages/Register"
import Services from "./pages/Services"
import Home from "./pages/Home"
import Header from "./components/Header"
import Footer from "./components/Footer"
import EmailVerification from "./pages/EmailVerification"
import Accordion from "./pages/Accordion"
import PacketCapture from "./pages/packetCapture"
import CsvAnalyzer from "./pages/CsvAnalyzer"
// import {Toaster} from 'react-hot-toast'
import BlockIP from "./pages/BlockIp"
import { useEffect } from "react"
import { Toaster } from "../src/components/ui/sonner"

import { useAuthStore } from "./store/authStore"
import ForgotPassword from "./pages/ForgotPassword"
import ResetPassword from "./pages/ResetPassword"
import { Loader } from "lucide-react"
import ServicePage from "./pages/ServicePage"

const appRouter = createBrowserRouter(
  
  [
  {
    path:"/",
    element: <Home/>,
    children: [
      {
        path:"/",
        element: <Home/>
      },
      {
        path:'/FAQ',
        element:<Accordion/>
      }
      
]}
,     {
        path:"/login",
        element: <Login/>
      },
      {
        path:"/PacketCapture",
        element:<PacketCapture/>
      },
      {
        path:"/BlockIp",
        element:<BlockIP/>
      },
      {
        path:"/csv_analyzer",
        element:<CsvAnalyzer/>
      },
      {
        path:"/register",
        element: <Register/>,
      },
      {
        path:"/services",
        element: <Services/>
      },
      {
        path:"/verify-email",
        element: <EmailVerification/>
      },
      {
        path:"/forgot-password",
        element: <ForgotPassword/>
      },
      {
        path:"/reset-password",
        element: <ResetPassword/>
      },
      {
        path:'/service',
        element:<ServicePage/>
      },
      {
        path:"/about",
        element: <About/>
      },
])



const App = () => {
  const { checkAuth, isCheckingAuth } = useAuthStore();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  if (isCheckingAuth) return (
    <div className="flex items-center justify-center h-screen">
      <Loader className="size-10 animate-spin" />
    </div>
  )

  return (
    <main>
      <RouterProvider router={appRouter}>
        <Header/>
        <main>
          <Outlet/>
        </main>
        <Footer/>
      </RouterProvider>
      <Toaster/>
    </main>
  )
}

export default App
