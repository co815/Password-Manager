import React, { useState } from 'react'
import Box from '@mui/material/Box'
import Tabs from '@mui/material/Tabs'
import Tab from '@mui/material/Tab'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'

function Auth () {
    const [tab, setTab] = useState(0)
    const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
        setTab(newValue)
    }
  return (
      <Box>
          <Tabs value={tab} onChange={handleTabChange} variant="fullWidth" sx={{ mb: 3, width: '100%' }}>
              <Tab label="Log In" sx={{ fontWeight: 600 }} />
              <Tab label="Sign Up" sx={{ fontWeight: 600 }} />
          </Tabs>
          {tab === 0 ? (
              <Box component="form" sx={{ width: '100%', maxWidth: 260, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField label="Email" type="email" variant="outlined" size="small" required fullWidth />
                  <TextField label="Password" type="password" variant="outlined" size="small" required fullWidth />
                  <Button type="submit" variant="contained" sx={{ mt: 1, fontWeight: 600, background: 'linear-gradient(90deg, #6366f1 0%, #06b6d4 100%)' }} fullWidth>
                      Log In
                  </Button>
              </Box>
          ) : (
              <Box component="form" sx={{ width: '100%', maxWidth: 260, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField label="Name" type="text" variant="outlined" size="small" required fullWidth />
                  <TextField label="Email" type="email" variant="outlined" size="small" required fullWidth />
                  <TextField label="Password" type="password" variant="outlined" size="small" required fullWidth />
                  <Button type="submit" variant="contained" sx={{ mt: 1, fontWeight: 600, background: 'linear-gradient(90deg, #6366f1 0%, #06b6d4 100%)' }} fullWidth>
                      Sign Up
                  </Button>
              </Box>
          )}
      </Box>)
}

export default Auth