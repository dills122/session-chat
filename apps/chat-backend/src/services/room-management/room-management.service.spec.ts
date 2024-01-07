import { Test, TestingModule } from '@nestjs/testing';
import { RoomManagementService } from './room-management.service';

describe('RoomManagementService', () => {
  let service: RoomManagementService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RoomManagementService]
    }).compile();

    service = module.get<RoomManagementService>(RoomManagementService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
