import { Test, TestingModule } from '@nestjs/testing';
import { RoomManagementService } from './room-management.service';
import { RedisModule } from '../../infrastructure/redis/redis.module';
import { ConfigService } from '@nestjs/config';

describe('RoomManagementService', () => {
  let service: RoomManagementService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [RedisModule],
      providers: [RoomManagementService, ConfigService]
    }).compile();

    service = module.get<RoomManagementService>(RoomManagementService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
