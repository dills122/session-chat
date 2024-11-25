import { Test, TestingModule } from '@nestjs/testing';
import { RoomManagementService } from './room-management.service';
import { RedisModule } from '../../infrastructure/redis/redis.module';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { mockRedisRepositoryService } from '../../../mocks/redis.service.mock';
// import { RedisRepositoryInterface } from '../../infrastructure/redis/redis.repository.interface';

describe('RoomManagementService', () => {
  let service: RoomManagementService;
  // let redisService: jest.Mocked<RedisRepositoryInterface>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [RedisModule],
      providers: [
        RoomManagementService,
        ConfigService,
        {
          provide: RedisService,
          useValue: mockRedisRepositoryService
        }
      ]
    }).compile();

    service = module.get<RoomManagementService>(RoomManagementService);
    // redisService = module.get<RedisRepositoryInterface>('RedisRepositoryInterface');
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('isReferrerALink', () => {
    it('should return false if referrer is re-auth', () => {
      expect(service.isReferrerALink('re-auth')).toBeFalsy();
    });
    it('should return false if referrer is creator', () => {
      expect(service.isReferrerALink('creator')).toBeFalsy();
    });
    it('should return false if referrer is faker/fake', () => {
      expect(service.isReferrerALink('faker/fake')).toBeTruthy();
    });
  });
});
