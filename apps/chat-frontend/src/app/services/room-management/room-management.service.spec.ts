import { TestBed } from '@angular/core/testing';

import { RoomManagementService } from './room-management.service';
import { SocketIoConfig, SocketIoModule } from 'ngx-socket-io';

describe('RoomManagementService', () => {
  let service: RoomManagementService;

  const config: SocketIoConfig = {
    // url: 'https://ws.dsteele.dev/chat',
    url: 'localhost:3001/chat',
    options: {
      transports: ['websocket'],
      timeout: 15000
    }
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SocketIoModule.forRoot(config)]
    });
    service = TestBed.inject(RoomManagementService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
