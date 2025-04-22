import {  useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaBars, FaTimes } from "react-icons/fa";
import { useTranslation } from "react-i18next";
import useAuthStore from "../store/authStore.js";
// Import Zustand store

const Header = () => {
  const [isOpen, setIsOpen] = useState(false);
  const { isAuthenticated, logout } = useAuthStore();
  const { t } = useTranslation();

  const navigate = useNavigate();

  // useEffect(() => {
  //   checkAuth(); // Ensure user authentication state is correct on page load
  // }, []);

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  return (
    <div>
      <header className="flex justify-between items-center p-4 lg:border-b-2 lg:border-gray-200 lg:mx-8">
        <h1 className="text-2xl font-bold mx-4 lg:mx-10">{t("firewall")}</h1>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-6 mx-7">
          <Link to="/" className="hover:text-gray-700">{t("home")}</Link>
          <Link to="/about" className="hover:text-gray-700">{t("about")}</Link>
          <Link to="/service" className="hover:text-gray-700">{t("service")}</Link>
          <div className="flex space-x-3">
            {isAuthenticated ? (
              <button
                onClick={handleLogout}
                className="border-2 px-4 py-2 rounded-sm hover:bg-gray-200"
              >
                {t("logout")}
              </button>
            ) : (
              <>
                <Link to="/login">
                  <button className="border-2 px-4 py-2 rounded-sm hover:bg-gray-200">
                    {t("login")}
                  </button>
                </Link>
                <Link to="/register">
                  <button className="bg-black text-white px-4 py-2 rounded-sm hover:bg-gray-800">
                    {t("register")}
                  </button>
                </Link>
              </>
            )}
          </div>
        </nav>

        {/* Mobile Menu Button */}
        <button
          onClick={toggleMenu}
          className="md:hidden focus:outline-none mx-4"
          aria-label="Toggle menu"
        >
          {isOpen ? <FaTimes size={24} /> : <FaBars size={24} />}
        </button>
      </header>

      {/* Mobile Navigation */}
      {isOpen && (
        <nav className="lg:hidden bg-gray-100">
          <ul className="flex flex-col items-center py-4 space-y-2">
            <li>
              <Link to="/" onClick={toggleMenu} className="block px-4 py-2 hover:bg-gray-200">
                {t("home")}
              </Link>
            </li>
            <li>
              <Link to="/about" onClick={toggleMenu} className="block px-4 py-2 hover:bg-gray-200">
                {t("about")}
              </Link>
            </li>
            <li>
              <Link to="/services" onClick={toggleMenu} className="block px-4 py-2 hover:bg-gray-200">
                {t("services")}
              </Link>
            </li>
            <li className="flex space-x-3">
              {isAuthenticated ? (
                <button
                  onClick={() => {
                    handleLogout();
                    toggleMenu();
                  }}
                  className="border-2 px-4 py-2 rounded-sm hover:bg-gray-200"
                >
                  {t("logout")}
                </button>
              ) : (
                <>
                  <Link to="/login" onClick={toggleMenu}>
                    <button className="border-2 px-4 py-2 rounded-sm hover:bg-gray-200">
                      {t("login")}
                    </button>
                  </Link>
                  <Link to="/register" onClick={toggleMenu}>
                    <button className="bg-black text-white px-4 py-2 rounded-sm hover:bg-gray-800">
                      {t("register")}
                    </button>
                  </Link>
                </>
              )}
            </li>
          </ul>
        </nav>
      )}
    </div>
  );
};

export default Header;
