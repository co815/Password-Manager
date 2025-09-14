import { Box, Typography } from '@mui/material'

function Info () {
  return (
      <Box sx={{ p: 4, width: '100%', maxWidth: 400, textAlign: 'center' }}>
        <Typography variant="h4" fontWeight={700} mb={2} align="center">
          Password Manager
        </Typography>
        <Typography variant="body1" align="center">
            Securely store and manage your passwords in one place.<br />
            Fast, simple, and private.
        </Typography>
      </Box>
  )
}

export default Info