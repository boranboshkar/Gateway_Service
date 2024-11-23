
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import { ClientRequest } from 'http';
import cors from 'cors';
import 'dotenv/config';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { Request, Response, NextFunction } from 'express';
import {
    loginRoute,
    logoutRoute,
    signupRoute,
    userProfileRoute,
    authenticate,
    updateUserPermission,
    ensureAdminUserExists,
    getAllUsers
} from './routes.js';

import {
    LOGIN_PATH,
    LOGOUT_PATH,
    SIGNUP_PATH,
    USERPROFILE_PATH,
} from './const.js';

dotenv.config();

await mongoose.connect(process.env.dbUri);
await ensureAdminUserExists()
const port = process.env.PORT  ;

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
    console.log('Incoming request:', req.method, req.path,req.body,req.headers,req);
    next();
  });

/* TODO: set CORS headers appropriately using the cors middleware */
app.use(cors({
    origin: process.env.ORIGIN, // Make sure this matches your frontend URL exactly
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true, // To allow sending cookies and authorization headers with the requests
}));
// app.use(cors({
//   origin: true, 
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   credentials: true, // To allow sending cookies and authorization headers with the requests
// }));



/* ========== */

app.post(LOGIN_PATH, loginRoute);
app.post(LOGOUT_PATH, logoutRoute);
app.post(SIGNUP_PATH, signupRoute);
app.get(USERPROFILE_PATH, userProfileRoute);
  
function setupProxy(targetUrl:string, sharedApiToken:string) {
    return createProxyMiddleware({
      target: targetUrl,
      changeOrigin: true,
      pathRewrite: function(path, req) {
        // Dynamically determine the base path ('events' or 'orders')
        const basePathMatch = path.match(/^\/api\/(events|orders)/);
        const basePath = basePathMatch ? basePathMatch[1] : '';
        
        // Remove '/api/{basePath}' from the path and prepend it back without '/api'
        let newPath = `/${basePath}` + path.replace(/^\/api\/(events|orders)/, '');

        // Check if the user is authenticated and user details are available
        if (req.user) {
          // Encode user details as query parameters
          const queryParams = new URLSearchParams({
            userId: req.user._id.toString(),
            permission: req.user.permission,
            username: req.user.username
          }).toString();
  
        //   Append query parameters to the newPath
          newPath += (newPath.includes('?') ? '&' : '?') + queryParams;
        }
        console.log(`Original path: ${path}, New path: ${newPath}`);
        return newPath;
      },
      onProxyReq: (proxyReq:ClientRequest,req:Request) => {
        // console.log('Proxy Request Headers:', proxyReq.getHeaders());
        // console.log('Proxy Request body:', proxyReq.body);
        if (req.body) {
            let bodyData = JSON.stringify(req.body);
            // Set the appropriate Content-Type header
            proxyReq.setHeader('Content-Type','application/json'); 
            proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
            console.log('the body to forward is :', bodyData)
            proxyReq.setHeader('Authorization', `Bearer ${sharedApiToken}`);
            proxyReq.write(bodyData);
            proxyReq.end(); 
        }
      }
    });
  }

app.use(authenticate); 
app.put('/api/promote', updateUserPermission);
app.get('/api/users', getAllUsers);

// Proxy middleware for Events Service
app.use('/api/events', setupProxy(process.env.EVENTS_SERVICE_BASE_URL, process.env.EVENTS_SHARED_API_TOKEN));

//Proxy middleware for Orders Service
app.use('/api/orders', setupProxy(process.env.ORDERS_SERVICE_BASE_URL, process.env.ORDERS_SHARED_API_TOKEN));

app.listen(port, () => {
    console.log(`Server running! port ${port}`);
});
