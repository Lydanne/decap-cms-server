import bcrypt from "bcrypt";

export function createPasswordHash(password: string): Promise<string> {
  return bcrypt.hash(password + process.env.PASSWD_SALT, 10);
}

export function comparePassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password + process.env.PASSWD_SALT, hash);
}
