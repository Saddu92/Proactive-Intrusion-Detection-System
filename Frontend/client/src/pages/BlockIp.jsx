import { useState, useEffect } from "react";

const BlockIP = () => {
    const [ip, setIp] = useState("");
    const [blockedIps, setBlockedIps] = useState([]);

    // Fetch blocked IPs on component mount
    useEffect(() => {
        fetchBlockedIps();
    }, []);

    // Fetch blocked IPs
    const fetchBlockedIps = async () => {
        try {
            const res = await fetch("http://127.0.0.1:8000/blocked-ips/");
            const data = await res.json();
            setBlockedIps(data.blocked_ips || []);
        } catch (error) {
            console.error("Error fetching blocked IPs:", error);
            setBlockedIps([]);
        }
    };

    // Block IP function
    const blockIp = async () => {
        if (!ip) return;
        await fetch("http://127.0.0.1:8000/block-ip/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        });
        setBlockedIps((prev) => [...prev, ip]); 
        setIp("");
    };
    

    // Unblock IP function
    const unblockIp = async (unblockIp) => {
        await fetch("http://127.0.0.1:8000/unblock-ip/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: unblockIp }),
        });
        setBlockedIps((prev) => prev.filter((item) => item !== unblockIp)); 
    };
    

    return (
        <div className="mt-14 ">
        <div className="p-12 max-w-lg mx-auto bg-white shadow-2xl rounded-lg ">
            <h2 className="text-2xl font-bold mb-4 text-center">Block IP</h2>
            <div className="flex gap-2 mb-4">
                <input
                    type="text"
                    placeholder="Enter IP Address"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    className="border p-2 flex-grow rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                    onClick={blockIp}
                    className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg shadow"
                >
                    Block
                </button>
            </div>

            <h3 className="text-lg font-semibold mb-2">Blocked IPs</h3>
            <ul className="space-y-2">
                {blockedIps.length > 0 ? (
                    blockedIps.map((blockedIp) => (
                        <li key={blockedIp} className="flex justify-between items-center p-3 bg-gray-100 rounded-lg shadow">
                            <span className="font-medium">{blockedIp}</span>
                            <button
                                onClick={() => unblockIp(blockedIp)}
                                className="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded-lg shadow"
                            >
                                Unblock
                            </button>
                        </li>
                    ))
                ) : (
                    <li className="text-gray-500">No blocked IPs</li>
                )}
            </ul>
        </div>
        </div>
    );
};

export default BlockIP;