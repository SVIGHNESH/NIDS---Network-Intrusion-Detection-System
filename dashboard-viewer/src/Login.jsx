import { useState } from "react";

const VALID_EMAIL = "admin@nids.com";
const VALID_PASSWORD = "password123";

export default function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    // Validate email format
    if (!validateEmail(email)) {
      setError("Please enter a valid email address");
      setIsLoading(false);
      return;
    }

    // Validate password minimum length
    if (password.length < 6) {
      setError("Password must be at least 6 characters");
      setIsLoading(false);
      return;
    }

    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 500));

    // Check credentials
    if (email === VALID_EMAIL && password === VALID_PASSWORD) {
      onLogin();
    } else {
      setError("Invalid email or password");
      setIsLoading(false);
    }
  };

  return (
    <div
      style={{
        background: "#080808",
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
      `}</style>

      <div
        style={{
          background: "#0d0d0d",
          border: "1px solid #1e1e1e",
          borderRadius: 8,
          padding: "40px 48px",
          width: "100%",
          maxWidth: 380,
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div
            style={{
              width: 48,
              height: 48,
              borderRadius: "50%",
              background: "#111",
              border: "2px solid #4299e1",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "0 auto 16px",
            }}
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#4299e1"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1
            style={{
              fontSize: 18,
              letterSpacing: 3,
              color: "#e0e0e0",
              textTransform: "uppercase",
              margin: 0,
            }}
          >
            NIDS Login
          </h1>
          <p
            style={{
              fontSize: 11,
              color: "#444",
              marginTop: 8,
              letterSpacing: 1,
            }}
          >
            Network Intrusion Detection System
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 20 }}>
            <label
              style={{
                display: "block",
                fontSize: 10,
                letterSpacing: 1.5,
                color: "#555",
                textTransform: "uppercase",
                marginBottom: 8,
              }}
            >
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@nids.com"
              style={{
                width: "100%",
                padding: "12px 14px",
                background: "#080808",
                border: "1px solid #1e1e1e",
                borderRadius: 4,
                color: "#e0e0e0",
                fontSize: 13,
                fontFamily: "'JetBrains Mono', monospace",
                boxSizing: "border-box",
                outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "#4299e1")}
              onBlur={(e) => (e.target.style.borderColor = "#1e1e1e")}
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label
              style={{
                display: "block",
                fontSize: 10,
                letterSpacing: 1.5,
                color: "#555",
                textTransform: "uppercase",
                marginBottom: 8,
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min 6 characters"
              minLength={6}
              style={{
                width: "100%",
                padding: "12px 14px",
                background: "#080808",
                border: "1px solid #1e1e1e",
                borderRadius: 4,
                color: "#e0e0e0",
                fontSize: 13,
                fontFamily: "'JetBrains Mono', monospace",
                boxSizing: "border-box",
                outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "#4299e1")}
              onBlur={(e) => (e.target.style.borderColor = "#1e1e1e")}
            />
          </div>

          {error && (
            <div
              style={{
                background: "#3a0a0a",
                border: "1px solid #e53e3e",
                borderRadius: 4,
                padding: "10px 12px",
                marginBottom: 20,
                fontSize: 11,
                color: "#fc8181",
                textAlign: "center",
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            style={{
              width: "100%",
              padding: "12px",
              background: isLoading ? "#2d3748" : "#4299e1",
              border: "none",
              borderRadius: 4,
              color: "#fff",
              fontSize: 12,
              letterSpacing: 2,
              textTransform: "uppercase",
              fontFamily: "'JetBrains Mono', monospace",
              cursor: isLoading ? "not-allowed" : "pointer",
              opacity: isLoading ? 0.6 : 1,
              transition: "background 0.2s",
            }}
            onMouseEnter={(e) => !isLoading && (e.target.style.background = "#3182ce")}
            onMouseLeave={(e) => !isLoading && (e.target.style.background = "#4299e1")}
          >
            {isLoading ? "Authenticating..." : "Sign In"}
          </button>
        </form>

        <div
          style={{
            marginTop: 24,
            textAlign: "center",
            fontSize: 10,
            color: "#333",
            letterSpacing: 1,
          }}
        >
          Restricted access • Authorized personnel only
        </div>
      </div>
    </div>
  );
}