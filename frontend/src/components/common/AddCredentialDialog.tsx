import React, { useState } from "react";
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    Button,
    Box,
} from "@mui/material";

export interface Credential {
    name: string;
    username: string;
    password?: string;
    link?: string;
}

interface AddCredentialDialogProps {
    open: boolean;
    onClose: () => void;
    onAdd: (newCredential: Credential) => void;
}

const AddCredentialDialog: React.FC<AddCredentialDialogProps> = ({
                                                                     open,
                                                                     onClose,
                                                                     onAdd,
                                                                 }) => {
    const [name, setName] = useState<string>("");
    const [email, setEmail] = useState<string>("");
    const [password, setPassword] = useState<string>("");
    const [link, setLink] = useState<string>("");

    const handleSubmit = () => {
        if (!name) return; // simple validation
        onAdd({ name, username: email, password, link });
        // Reset fields
        setName("");
        setEmail("");
        setPassword("");
        setLink("");
        onClose();
    };

    return (
        <Dialog
            open={open}
            onClose={onClose}
            maxWidth="sm"
            fullWidth // makes the dialog take more horizontal space
        >
            <DialogTitle>Add New Credential</DialogTitle>
            <DialogContent>
                <Box display="flex" flexDirection="column" gap={2} mt={1}>
                    <TextField
                        label="Name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        fullWidth
                        required
                    />
                    <TextField
                        label="Email / Username"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        fullWidth
                    />
                    <TextField
                        label="Password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        fullWidth
                    />
                    <TextField
                        label="Website / Link"
                        value={link}
                        onChange={(e) => setLink(e.target.value)}
                        fullWidth
                    />
                </Box>
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose}>Cancel</Button>
                <Button variant="contained" onClick={handleSubmit}>
                    Add
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default AddCredentialDialog;
