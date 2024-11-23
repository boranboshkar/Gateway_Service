// types/express/index.d.ts
import 'express';

declare module 'express-serve-static-core' {
  interface Request {
    user?: { _id: string; username: string; permission: string }; // Adjust the type according to your actual user object structure
  }
}
