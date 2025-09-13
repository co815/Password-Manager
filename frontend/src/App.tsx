import axios from 'axios'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { useState } from 'react'

function App() {
    // State to hold the message from the backend
    const [message, setMessage] = useState("");
    const handleClick = async () => {
        console.log('Button clicked');
        try {
            const response = await axios.get('http://localhost:8080/api/health');
            setMessage(JSON.stringify(response.data));
            console.log('Response from backend:', JSON.stringify(response.data));
        }
        catch (error) {
            console.error('Error fetching data:', error);
            setMessage('Error fetching data');
        }
    }

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={handleClick}>
            {message || 'Fetch Message from Backend'}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  )
}

export default App
