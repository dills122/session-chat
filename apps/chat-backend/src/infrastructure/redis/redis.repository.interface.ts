export interface RedisRepositoryInterface {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  setWithExpiry(key: string, value: string, expiry: number): Promise<void>;
}
