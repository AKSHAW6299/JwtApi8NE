import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Loading environment variables from .env file
dotenv.config();

const connectToDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            // useNewUrlParser: true,
            // useUnifiedTopology: true,
            dbName: "JwtAuthDB1",
        });
        console.log('✅ MongoDB connected successfully!');
    } catch (err) {
        console.error('❌ MongoDB connection failed:', err.message);
    }
};

export default connectToDB;