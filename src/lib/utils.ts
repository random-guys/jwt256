import jwt from "jsonwebtoken";
import crypto, { CipherGCMTypes } from "crypto";

export class JWT {
  private jwt_secret: string;

  constructor(secret: string) {
    this.jwt_secret = secret;
  }

  sign = (payload: any) => {
    return new Promise<string>((resolve, reject) => {
      jwt.sign(payload, this.jwt_secret, { expiresIn: "24h" }, (err, token) => {
        if (err) reject(err);
        resolve(token);
      });
    });
  };

  decode = <T = any>(token: string) => {
    return new Promise<T>((resolve, reject) => {
      jwt.verify(token, this.jwt_secret, (err, decoded: any) => {
        if (err) reject(err);
        resolve(decoded as T);
      });
    });
  };
}

export class AES256 {
  private secret_key: Buffer;
  private ALGO: CipherGCMTypes = "aes-256-gcm";

  constructor(key) {
    this.secret_key = key;
  }

  // encrypt returns base64-encoded ciphertext
  encrypt = (str: string) => {
    const iv = Buffer.from(crypto.randomBytes(16).toString("utf8"), "utf8");
    const cipher = crypto.createCipheriv(this.ALGO, this.secret_key, iv);

    let enc = cipher.update(str, "utf8", "base64");
    enc += cipher.final("base64");
    return { enc, iv, tag: cipher.getAuthTag() };
  };

  // decrypt decodes base64-encoded ciphertext into a utf8-encoded string
  decrypt = (enc: string, iv: Buffer, authTag: Buffer) => {
    const decipher = crypto.createDecipheriv(this.ALGO, this.secret_key, iv);
    decipher.setAuthTag(authTag);
    let str = decipher.update(enc, "base64", "utf8");
    str += decipher.final("utf8");
    return str;
  };
}
