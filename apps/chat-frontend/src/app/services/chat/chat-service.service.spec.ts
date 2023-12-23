import { TestBed } from '@angular/core/testing';
import { Socket } from 'ngx-socket-io';

import { ChatServiceService } from './chat-service.service';

describe('ChatServiceService', () => {
  let service: ChatServiceService;
  let socketIO: jasmine.SpyObj<Socket>;
  // const messageMock = {
  //   uid: 'UUID',
  //   room: 'roomId',
  //   token: 'TOKEN',
  //   message: 'msg',
  //   timestamp: new Date().toISOString()
  // } as MessageFormat;

  beforeEach(() => {
    socketIO = jasmine.createSpyObj('Socket', ['emit', 'fromEvent']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Socket,
          useValue: socketIO
        }
      ]
    });
    service = TestBed.inject(ChatServiceService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
