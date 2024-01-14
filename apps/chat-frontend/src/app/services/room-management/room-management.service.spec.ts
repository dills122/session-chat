import { TestBed } from '@angular/core/testing';

import { RoomManagementService } from './room-management.service';

describe('RoomManagementService', () => {
  let service: RoomManagementService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(RoomManagementService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
