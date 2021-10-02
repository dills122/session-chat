import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { Socket } from 'ngx-socket-io';

import { LoginService } from './login.service';

describe('LoginService', () => {
  let service: LoginService;
  let routerSpy: jasmine.SpyObj<Router>;
  let socketIO: jasmine.SpyObj<Socket>;

  beforeEach(() => {
    routerSpy = jasmine.createSpyObj('Router', ['navigate']);
    socketIO = jasmine.createSpyObj('Socket', ['emit', 'fromEvent']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Router,
          useValue: routerSpy
        },
        {
          provide: Socket,
          useValue: socketIO
        }
      ]
    });
    service = TestBed.inject(LoginService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
