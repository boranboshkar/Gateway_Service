
import * as mongoose from 'mongoose';
//TODO: change the defualt
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    permission: { type: String, default: 'U' },
});

export default mongoose.model('User', userSchema);
