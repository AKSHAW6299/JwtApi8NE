import express from 'express'
import connectToDB from './db.js'
import dotenv from 'dotenv';
import UserRoutes from './routes/auth.routes.js'
import cookieParser from 'cookie-parser';



const app = express()
const port = process.env.port || 6000
dotenv.config();

// 1) Middlewares
app.use(express.json())
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 2) Function call to connect to DB
connectToDB();

// 3) To use product routes we have to MOUNT the router file.
app.use('/api/auth', UserRoutes)

app.listen(port, () => {
    console.log(`Server app listening on port ${port}`)
})
