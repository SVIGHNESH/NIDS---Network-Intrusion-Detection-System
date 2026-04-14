import { useState } from "react";
import NIDSDashboard from "./NIDSDashboard";
import Login from "./Login";

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  return isLoggedIn ? <NIDSDashboard onLogout={() => setIsLoggedIn(false)} /> : <Login onLogin={() => setIsLoggedIn(true)} />;
}

export default App;