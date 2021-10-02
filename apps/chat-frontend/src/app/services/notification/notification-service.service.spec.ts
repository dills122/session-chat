import { TestBed } from '@angular/core/testing';
import { Socket } from 'ngx-socket-io';

import { NotificationServiceService } from './notification-service.service';

describe('NotificationServiceService', () => {
  let service: NotificationServiceService;
  let socketIO: jasmine.SpyObj<Socket>;

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
    service = TestBed.inject(NotificationServiceService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
