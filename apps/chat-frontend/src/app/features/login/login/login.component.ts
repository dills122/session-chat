import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

import { AuthServiceService } from 'src/app/services/auth/auth-service.service';
import { SessionStorageService } from 'src/app/services/session-storage/session-storage.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private username: string;

  constructor(
    private sessionStorageService: SessionStorageService,
    private authService: AuthServiceService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.authService.subscribeLogin().subscribe((resp) => {
      if (resp.uid === this.userName) {
        this.setupSessionStorage({
          token: resp.token,
          room: resp.room,
          uid: this.userName
        });
        this.router.navigate(['/chat-room']);
      } else {
        console.log('Not correct response');
      }
    });
  }

  private setupSessionStorage({ room, token, uid }: { room: string; token: string; uid: string }) {
    this.sessionStorageService.setItem(room, room);
    this.sessionStorageService.setItem('jwt_token', token);
    this.sessionStorageService.setItem('uid', uid);
  }

  login() {
    this.authService.attemptLogin({
      room: 'general',
      uid: this.userName,
      timestamp: new Date().toISOString()
    });
  }

  get userName(): string {
    return this.username;
  }

  set userName(val: string) {
    this.username = val;
  }
}
