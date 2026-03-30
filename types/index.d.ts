import { RequestHandler, Request, Response, NextFunction } from 'express';

// ========== Core ==========

type DoneCallback = (err: Error | null, user?: any, info?: { message: string }) => void;
type SerializeCallback = (err: Error | null, id?: string | number) => void;
type DeserializeCallback = (err: Error | null, user?: any) => void;

interface SessionOptions {
  secret?: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  secure?: boolean;
  httpOnly?: boolean;
  maxAge?: number;
  cookie?: Record<string, any>;
  store?: any;
}

interface AuthenticateOptions {
  successRedirect?: string;
  failureRedirect?: string;
  failureMessage?: string;
}

interface ProtectOptions {
  redirect?: string;
  message?: string;
}

export class EasyAuth {
  strategies: Record<string, any>;

  use(name: string, strategy: any): this;
  use(strategy: any): this;

  serializeUser(fn: (user: any, done: SerializeCallback) => void): this;
  deserializeUser(fn: (id: string | number, done: DeserializeCallback) => void): this;

  initialize(options?: SessionOptions): RequestHandler[];
  authenticate(strategyName: string, options?: AuthenticateOptions): RequestHandler;
  protect(options?: ProtectOptions): RequestHandler;
  authorize(...roles: string[]): RequestHandler;
}

// ========== Strategies ==========

interface LocalStrategyOptions {
  usernameField?: string;
  passwordField?: string;
}

type LocalVerifyCallback = (
  username: string,
  password: string,
  done: DoneCallback
) => void | Promise<void>;

export class LocalStrategy {
  name: string;
  constructor(verify: LocalVerifyCallback);
  constructor(options: LocalStrategyOptions, verify: LocalVerifyCallback);
  authenticate(req: Request, done: DoneCallback): void;
}

interface JwtStrategyOptions {
  secret: string;
  extractFrom?: 'header' | 'cookie' | 'query';
  cookieName?: string;
  queryParam?: string;
  headerScheme?: string;
}

type JwtVerifyCallback = (
  payload: Record<string, any>,
  done: DoneCallback
) => void | Promise<void>;

export class JwtStrategy {
  name: string;
  constructor(options: JwtStrategyOptions, verify: JwtVerifyCallback);
  extractToken(req: Request): string | null;
  authenticate(req: Request, done: DoneCallback): void;
}

interface GoogleStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string[];
}

interface GoogleProfile {
  id: string;
  displayName: string;
  email: string;
  picture: string;
  raw: Record<string, any>;
}

type GoogleVerifyCallback = (
  accessToken: string,
  refreshToken: string,
  profile: GoogleProfile,
  done: DoneCallback
) => void | Promise<void>;

export class GoogleStrategy {
  name: string;
  constructor(options: GoogleStrategyOptions, verify: GoogleVerifyCallback);
  redirectMiddleware(): RequestHandler;
  authenticate(req: Request, done: DoneCallback): Promise<void>;
}

// ========== Utilities ==========

export function hashPassword(password: string, rounds?: number): Promise<string>;
export function comparePassword(password: string, hash: string): Promise<boolean>;
export function generateToken(
  payload: Record<string, any>,
  secret: string,
  options?: { expiresIn?: string | number; [key: string]: any }
): string;
export function verifyToken(token: string, secret: string): Record<string, any> | null;

// ========== Express Augmentation ==========

declare global {
  namespace Express {
    interface Request {
      user?: any;
      isAuthenticated(): boolean;
      logout(callback?: (err?: Error) => void): void;
    }
  }
}
