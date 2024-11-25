import { RedisRepositoryInterface } from '../src/infrastructure/redis/redis.repository.interface';

export const mockRedisRepositoryService: jest.Mocked<RedisRepositoryInterface> = {
  get: jest.fn(),
  set: jest.fn(),
  delete: jest.fn(),
  setWithExpiry: jest.fn()
};
