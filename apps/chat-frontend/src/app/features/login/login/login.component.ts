import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

import { LocalStorageService } from '../../../services/local-storage/local-storage.service';
import { AuthServiceService } from 'src/app/services/auth/auth-service.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private username: string;

  constructor(
    private localStorageService: LocalStorageService,
    private router: Router,
    private authService: AuthServiceService
  ) {}

  ngOnInit(): void {
    this.authService.subscribeLogin().subscribe((resp) => {
      console.log(resp);
      if (resp.uid === this.userName) {
        this.localStorageService.setItem('room', resp.room);
        this.router.navigate(['/chat-room']);
      } else {
        console.log('Not correct response');
      }
    });
  }

  login() {
    this.localStorageService.setItem('username', this.userName);
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
    //do some extra work here
    this.username = val;
  }
}
