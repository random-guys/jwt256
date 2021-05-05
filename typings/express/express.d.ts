declare module Express {
  export interface Request {
    data: any;
    id: string;
    user: string;
  }
}
