export interface IAuthService {
  login(input: { email: string; password: string }): Promise<any>;
  register(input: { email: string; password: string; name?: string }): Promise<any>;
  logout(): Promise<void>;
  refresh(): Promise<any | null>;
}
