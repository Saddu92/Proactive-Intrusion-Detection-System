import React from "react";
import { Button } from "../components/ui/button";
import { ShieldCheck, Lock, Globe, Users } from "lucide-react";

const ServicePage = () => {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Hero Section */}
      <section className="text-center py-20 px-6">
        <h1 className="text-4xl font-bold mb-4">Proactive Firewall & Network Detection System</h1>
        <p className="text-lg text-gray-300 mb-6">Real-time cybersecurity threat detection & prevention with AI-driven insights.</p>
        <Button className="bg-blue-600 hover:bg-blue-700 px-6 py-3 text-lg">Get Started</Button>
      </section>

      {/* Features Section */}
      <section className="py-16 px-6 grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <FeatureCard icon={<ShieldCheck size={40} />} title="AI-Powered Detection" desc="Advanced ML models for real-time threat analysis." />
        <FeatureCard icon={<Lock size={40} />} title="Dynamic IP Blocking" desc="Automatically block malicious IPs instantly." />
        <FeatureCard icon={<Globe size={40} />} title="Network Traffic Monitoring" desc="Analyze live network packets for anomalies." />
        <FeatureCard icon={<Users size={40} />} title="User Authentication" desc="Ensure only authorized access with robust security." />
      </section>

      {/* Why Choose Us? */}
      <section className="py-16 text-center px-6">
        <h2 className="text-3xl font-semibold mb-6">Why Choose Our Security Solution?</h2>
        <p className="text-gray-300 max-w-3xl mx-auto">We provide a cutting-edge firewall system with adaptive learning, ensuring the highest security standards for your organization.</p>
      </section>

      {/* Testimonials */}
      <section className="py-16 px-6 bg-gray-800 text-center">
        <h2 className="text-3xl font-semibold mb-6">What Our Clients Say</h2>
        <div className="flex flex-wrap justify-center gap-6">
          <TestimonialCard name="John Doe" feedback="This system drastically improved our network security!" />
          <TestimonialCard name="Sarah Smith" feedback="Real-time threat detection has saved us from multiple attacks." />
          <TestimonialCard name="Steve Smith" feedback="User authentication saved me" />
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 text-center px-6">
        <h2 className="text-3xl font-semibold mb-4">Ready to Secure Your Network?</h2>
        <Button className="bg-green-500 hover:bg-green-600 px-6 py-3 text-lg">Contact Us</Button>
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

const TestimonialCard = ({ name, feedback }) => (
  <div className="bg-gray-700 p-6 rounded-lg max-w-sm shadow-md">
    <p className="text-gray-200 italic">"{feedback}"</p>
    <h4 className="mt-4 font-bold">- {name}</h4>
  </div>
);

export default ServicePage;