import React, { useState } from "react";
import axios from "axios";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { toast } from "sonner";

function PacketCapture() {
  const [loading, setLoading] = useState(false);
  const [predictions, setPredictions] = useState([]);
  const [alert, setAlert] = useState("");
  const [packetData, setPacketData] = useState([]);
  const [email, setEmail] = useState("");
  const [emailRegistered, setEmailRegistered] = useState(false);
  const [blockingIp, setBlockingIp] = useState(false);

  const startCapture = async () => {
    setLoading(true);
    setAlert("");

    try {
      const requestData = emailRegistered ? { email } : {};
      const response = await axios.post(
        "http://127.0.0.1:8000/start-capture-and-predict/",
        requestData
      );

      setPredictions(response.data.predictions);
      setPacketData(response.data.packet_data);

      if (response.data.predictions.includes(1)) {
        setAlert("🚨 Suspicious Network Activity Detected!");
      }

      if (response.data.http_alerts.email_sent) {
        toast.info("Security alerts will be sent to your email");
      }
    } catch (error) {
      console.error("Error:", error);
      if (emailRegistered === false) {
        toast.error("Please enter the email for Security Threat Updates");
      }
    } finally {
      setLoading(false);
    }
  };

  const blockMaliciousIp = async (ip) => {
    if (!ip) return;
    
    setBlockingIp(true);
    try {
      await axios.post("http://127.0.0.1:8000/block-ip/", { ip });
      toast.success(`Successfully blocked IP: ${ip}`);
    } catch (error) {
      console.error("Error blocking IP:", error);
      toast.error(`Failed to block IP: ${ip}`);
    } finally {
      setBlockingIp(false);
    }
  };

  // Data for charts
  const chartData = predictions.map((val, index) => ({
    id: index + 1,
    status: val ? "Threat" : "Normal",
  }));
  
  const pieData = [
    { name: "Normal", value: predictions.filter((p) => p === 0).length },
    { name: "Threat", value: predictions.filter((p) => p === 1).length },
  ];
  
  const colors = ["#34D399", "#F87171"]; // Green for Normal, Red for Threat

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center p-8">
      <h1 className="text-3xl font-bold">Proactive Firewall Dashboard</h1>
      {alert && <div className="bg-red-500 p-2 rounded mt-3">{alert}</div>}
      
      <button
        onClick={startCapture}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mt-5"
        disabled={loading}
      >
        {loading ? "Capturing..." : "Start Packet Capture"}
      </button>
      
      {!emailRegistered && (
        <div className="w-full max-w-md bg-gray-800 p-4 rounded-lg mt-4 mb-4">
          <h3 className="text-lg font-semibold mb-2">Get Security Alerts</h3>
          <div className="flex gap-2">
            <input
              type="email"
              placeholder="Your email for alerts"
              className="flex-1 bg-gray-700 text-white px-3 py-2 rounded"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              onClick={async () => {
                try {
                  await axios.post(
                    "http://127.0.0.1:8000/register-email-for-alerts/",
                    { email }
                  );
                  toast.success("Email registered for alerts");
                  setEmailRegistered(true);
                } catch (error) {
                  toast.error("Failed to register email");
                }
              }}
              className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded"
            >
              Register
            </button>
          </div>
        </div>
      )}
      
      {predictions.length > 0 && (
        <div className="w-full flex flex-col items-center mt-6">
          <div className="w-full flex justify-between">
            <div className="w-1/2">
              <h2 className="text-xl font-semibold">Packet Predictions</h2>
              <BarChart width={400} height={250} data={chartData}>
                <XAxis dataKey="id" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="status" fill="#8884d8" />
              </BarChart>
            </div>
            <div className="w-1/2">
              <h2 className="text-xl font-semibold">Threat Analysis</h2>
              <PieChart width={250} height={250}>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colors[index]} />
                  ))}
                </Pie>
              </PieChart>
            </div>
          </div>

          <div className="w-full mt-8">
            <h2 className="text-xl font-semibold">
              Captured Packets with Predictions
            </h2>
            <div className="overflow-x-auto">
              <table className="min-w-full bg-gray-800 text-white">
                <thead>
                  <tr>
                    <th className="px-4 py-2">Packet ID</th>
                    <th className="px-4 py-2">Source IP</th>
                    <th className="px-4 py-2">Destination IP</th>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Source Port</th>
                    <th className="px-4 py-2">Destination Port</th>
                    <th className="px-4 py-2">Packet Length</th>
                    <th className="px-4 py-2">Prediction</th>
                    <th className="px-4 py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {packetData.map((packet, index) => (
                    <tr 
                      key={index} 
                      className={`border-b border-gray-700 ${
                        predictions[index] === 1 ? "bg-red-900/30" : ""
                      }`}
                    >
                      <td className="px-4 py-2">{index + 1}</td>
                      <td className="px-4 py-2">{packet["Source IP"]}</td>
                      <td className="px-4 py-2">{packet["Destination IP"]}</td>
                      <td className="px-4 py-2">{packet["Protocol"]}</td>
                      <td className="px-4 py-2">{packet["Source Port"]}</td>
                      <td className="px-4 py-2">
                        {packet["Destination Port"]}
                      </td>
                      <td className="px-4 py-2">{packet["Packet Length"]}</td>
                      <td className="px-4 py-2">
                        <span
                          className={`px-2 py-1 rounded ${
                            predictions[index] === 1
                              ? "bg-red-500"
                              : "bg-green-500"
                          }`}
                        >
                          {predictions[index] === 1 ? "Threat" : "Normal"}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        {predictions[index] === 1 && (
                          <button
                            onClick={() => blockMaliciousIp(packet["Source IP"])}
                            disabled={blockingIp}
                            className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                          >
                            {blockingIp ? "Blocking..." : "Block IP"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PacketCapture;