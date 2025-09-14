import { BrowserRouter as Router, Routes, Route} from "react-router-dom";
import { Container } from "@mui/material";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
function App() {
    return (<Router>
        <Container>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/dashboard" element={<Dashboard />} />
            </Routes>
        </Container>
    </Router>)
}

export default App
