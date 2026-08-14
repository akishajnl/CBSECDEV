const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        // Securely fetching the connection string from the .env file
        // Notice the deprecated options have been removed
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Database Connection Error: ${error.message}`);
        process.exit(1);
    }
};

module.exports = connectDB;