import React from "react";
import { ShieldAlert, Users, Cpu, Lock, Globe } from "lucide-react";
import { Button } from "../components/ui/button";

const AboutPage = () => {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Hero Section */}
      <section className="text-center py-20 px-6 bg-gradient-to-r from-gray-900 via-slate-800 to-gray-900">
        <h1 className="text-4xl font-bold mb-4">About Us</h1>
        <p className="text-lg text-gray-300 max-w-2xl mx-auto">
          We are committed to **next-gen AI-powered cybersecurity**, ensuring proactive threat detection and prevention.
        </p>
      </section>

      {/* Mission & Vision */}
      <section className="py-16 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-semibold mb-4">Our Mission</h2>
          <p className="text-gray-300">
            Our mission is to provide organizations with **real-time AI-driven security**, defending networks from evolving cyber threats.
          </p>
        </div>
      </section>

      {/* Core Features */}
      <section className="py-16 px-6 grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <FeatureCard icon={<ShieldAlert size={40} />} title="Threat Prevention" desc="Proactive AI-based attack mitigation." />
        <FeatureCard icon={<Lock size={40} />} title="Secure Networks" desc="Robust security against unauthorized access." />
        <FeatureCard icon={<Cpu size={40} />} title="AI & Machine Learning" desc="Cutting-edge AI models for intelligent detection." />
        <FeatureCard icon={<Globe size={40} />} title="Global Protection" desc="Ensuring cybersecurity across networks worldwide." />
      </section>

      {/* Team Section */}
      <section className="py-16 px-6 bg-gray-800 text-center">
        <h2 className="text-3xl font-semibold mb-6">Meet Our Team</h2>
        <div className="flex flex-wrap justify-center gap-6">
          <TeamMember name="Alex Johnson" role="CEO & Cybersecurity Expert" />
          <TeamMember name="Sophia Lee" role="AI Researcher & Data Scientist" />
          <TeamMember name="Michael Davis" role="Security Analyst & Engineer" />
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 text-center px-6">
        <h2 className="text-3xl font-semibold mb-4">Ready to Enhance Your Security?</h2>
        <Button className="bg-green-600 hover:bg-green-700 px-6 py-3 text-lg">Contact Us</Button>
      </section>
    </div>
  );
};

const FeatureCard = ({ icon, title, desc }) => (
  <div className="bg-gray-800 p-6 rounded-lg text-center shadow-lg">
    <div className="text-blue-400 mb-3">{icon}</div>
    <h3 className="text-xl font-semibold mb-2">{title}</h3>
    <p className="text-gray-300">{desc}</p>
  </div>
);

const TeamMember = ({ name, role }) => (
  <div className="bg-gray-700 p-6 rounded-lg max-w-sm shadow-md">
    <h3 className="text-xl font-semibold">{name}</h3>
    <p className="text-gray-300">{role}</p>
  </div>
);

export default AboutPage;
