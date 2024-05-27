const express = require('express');
const { google } = require('googleapis');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors(
    {
        origin: process.env.CLIENT,
        credentials: true
    }
));
const PORT = 5000;

const CLIENT_ID = process.env.CLIENTID;
const CLIENT_SECRET = process.env.CLIENTSECRET;
const REDIRECT_URI = process.env.ORIGIN+'/oauth2callback';
const SCOPES = ['https://www.googleapis.com/auth/drive',"https://www.googleapis.com/auth/userinfo.email","https://www.googleapis.com/auth/userinfo.profile"];

const oAuth2Client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
);
app.use(cookieParser());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', process.env.CLIENT);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true'); // Set to true
    next();
  });
app.get('/auth', (req, res) => {
    const authUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
    });
    res.redirect(authUrl);
});
app.get('/signout', (req, res) => {
    res.clearCookie('tokens').send('Signed out');

});
app.get('/oauth2callback', async (req, res) => {
    const code = req.query.code;
    try {
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);
        // Store tokens in secure HTTP-only cookie
        delete tokens.refresh_token;
        res.cookie('tokens', JSON.stringify(tokens), { httpOnly: true, secure: false });
        res.redirect(process.env.CLIENT);
    } catch (error) {
        console.error('Error retrieving access token', error);
        res.status(500).send('Authentication failed');
    }
});

app.get('/userinfo', async (req, res) => {
    try {
        const tokens = req.cookies.tokens ? JSON.parse(req.cookies.tokens) : null;
        if (!tokens) {
            return res.status(401).send('Unauthorized');
        }
        oAuth2Client.setCredentials(tokens);
        const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client });
        const response = await oauth2.userinfo.get();
        const userData = {
            email: response.data.email,
            name: response.data.name,
            picture: response.data.picture
        };
        res.status(200).json(userData);
    } catch (error) {
        console.error('Error fetching user info', error);
        res.status(500).send('Failed to fetch user info');
    }
});


app.get('/files', async (req, res) => {
    const tokens = req.cookies.tokens ? JSON.parse(req.cookies.tokens) : null;
    if (!tokens) {
        return res.status(401).send('Unauthorized');
    }

    oAuth2Client.setCredentials(tokens);

    try {
        const {id} = req.query
        const drive = google.drive({ version: 'v3', auth: oAuth2Client });
        const response = await drive.files.export({
            fileId: id,
            mimeType: 'text/html',
        });
        res.send({data:response.data});
    } catch (error) {
        console.error('Error fetching files', error);
        res.status(500).send('Failed to fetch files');
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});