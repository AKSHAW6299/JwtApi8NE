import express from 'express'
import connectToDB from './db.js'
import dotenv from 'dotenv';
import UserRoutes from './routes/auth.routes.js'
import cookieParser from 'cookie-parser';
import cors from 'cors';

const app = express()
const port = process.env.port || 3000
dotenv.config();

// 1) Middlewares
app.use(express.json())
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS must be implemented in server.js, not in auth.middleware.js.
// REQUIRED for cookies in production
app.set("trust proxy", 1);
// SIMPLE CORS (nothing extra)
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
/////////////////////////////////////////


// 2) Function call to connect to DB
connectToDB();

// 3) To use product routes we have to MOUNT the router file.
app.use('/api/auth', UserRoutes)

app.listen(port, () => {
    console.log(`Server app listening on port ${port}`)
})
