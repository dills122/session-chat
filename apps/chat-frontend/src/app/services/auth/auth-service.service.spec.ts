import { TestBed } from '@angular/core/testing';
import { Socket } from 'ngx-socket-io';

import { AuthService } from './auth-service.service';

describe('AuthServiceService', () => {
  let service: AuthService;
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
    service = TestBed.inject(AuthService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
